// Package ssh — web-server virtual-host discovery. One-shot Plane-B probe over an open client.
//
// region MODULE_CONTRACT [DOMAIN(8): Observability; CONCEPT(7): VHosts; TECH(8): ssh,nginx,apache]
// @purpose Answer "what websites are hosted on this box?" by reading the actual web-server config
//
//	(nginx -T / apache2ctl -S) over SSH. This is the authoritative, keyless equivalent of a
//	"reverse-IP" lookup for VMs we own — no external crawled database needed.
//
// @io (ctx, *gossh.Client) -> (VHostList, error)
// @invariants
//   - The command is a compile-time constant: no user input reaches the shell (no RCE surface).
//   - Missing web server / no root -> empty list with Server="none", never an error.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: vhosts, virtual host, nginx, apache, server_name, namevhost, sites, web server
// STRUCTURE: ▶ ┌client┐ → ⚡ CombinedOutput(FIXED nginx-T + apache2ctl-S) → ◇ parse → ⊕ sites[] → ⎷ VHostList
package ssh

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// vhostCMD is the fixed web-server config + listener dump. Section markers make parsing robust.
// The =listen= section reveals which process actually serves :80/:443 even when the server is not
// nginx/apache (caddy, lighttpd, a docker-proxy, etc.) — so the probe is no longer blind to those.
const vhostCMD = `echo =id=; id -u 2>/dev/null
echo =listen=; (ss -tlnpH 2>/dev/null || netstat -tlnp 2>/dev/null) | grep -E ':(80|443)[[:space:]]' | head -30
echo =nginx=; (nginx -T 2>/dev/null || sudo -n nginx -T 2>/dev/null) | grep -iE '^[[:space:]]*(server_name|listen)[[:space:]]' | head -300
echo =apache=; ((apache2ctl -S 2>/dev/null || sudo -n apache2ctl -S 2>/dev/null) || (httpd -S 2>/dev/null || sudo -n httpd -S 2>/dev/null)) | grep -iE 'namevhost|^[[:space:]]*Server name:' | head -200
echo =caddy=; (cat /etc/caddy/Caddyfile 2>/dev/null || sudo -n cat /etc/caddy/Caddyfile 2>/dev/null) | grep -vE '^[[:space:]]*(#|//|$)' | head -120`

// VHost is one discovered site.
type VHost struct {
	Name string `json:"name"`
	Port string `json:"port"`
}

// VHostList is the parsed web-server vhost picture.
type VHostList struct {
	Server    string   `json:"server"` // nginx | apache | caddy | ... | unknown | none
	Sites     []VHost  `json:"sites"`
	Listening []string `json:"listening"` // "nginx:80" or ":80" (port without process when non-root)
	Root      bool     `json:"root"`      // whether the SSH user is root (governs config readability)
}

// region FUNC_Dialer_VHosts [DOMAIN(8): Observability; CONCEPT(7): VHosts; TECH(8): ssh]
// @purpose Dump and parse the web-server virtual-host config over an open SSH client.
// @complexity 6
// endregion FUNC_Dialer_VHosts
func (d *Dialer) VHosts(ctx context.Context, client *gossh.Client) (VHostList, error) {
	sess, err := client.NewSession()
	if err != nil {
		return VHostList{}, fmt.Errorf("vhosts: new session: %w", err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(vhostCMD)
	if err != nil {
		// grep exits non-zero when nothing matches; treat as no web server.
		return parseVHosts(string(out)), nil
	}
	return parseVHosts(string(out)), nil
}

var (
	reListenProc   = regexp.MustCompile(`:([0-9]+)\b.*users:\(\("([^"]+)"`)
	reListenPort   = regexp.MustCompile(`:([0-9]+)[[:space:]]`)
	reNginxListen  = regexp.MustCompile(`(?i)^\s*listen\s+([0-9]+)`)
	reNginxName    = regexp.MustCompile(`(?i)^\s*server_name\s+(.+?);`)
	reApacheNamevh = regexp.MustCompile(`(?i)port\s+(\d+)\s+namevhost\s+(\S+)`)
	reCaddySite    = regexp.MustCompile(`(?i)^([a-z0-9._:\-]+\.[a-z]{2,}|:[0-9]+|\[[0-9a-f:]+\])\s*\{`)
)

// knownServers maps a process name (from ss) to the canonical server label we report.
var knownServers = map[string]string{
	"nginx": "nginx", "apache2": "apache", "httpd": "apache",
	"caddy": "caddy", "lighttpd": "lighttpd", "haproxy": "haproxy",
	"traefik": "traefik", "envoy": "envoy", "docker-proxy": "docker",
}

// parseVHosts extracts sites + the actual serving process from the sectioned dump (tolerant).
func parseVHosts(out string) VHostList {
	sec := splitSections(out)
	vl := VHostList{Server: "none", Sites: []VHost{}, Listening: []string{}}

	// 0) Root detection (id -u == 0). Governs whether config dumps / process names are readable.
	if id := strings.TrimSpace(sec["id"]); id == "0" {
		vl.Root = true
	}

	// 1) What listens on :80/:443. Process names are only present as root (or sudo); as a non-root
	//    user we still capture the bare ports so the operator sees the web ports are open.
	detected := map[string]bool{}
	heard := map[string]bool{} // dedupe (dual-stack IPv4+IPv6 lists each port twice)
	for _, line := range strings.Split(sec["listen"], "\n") {
		if m := reListenProc.FindStringSubmatch(line); len(m) == 3 {
			proc := strings.ToLower(strings.TrimSpace(m[2]))
			entry := proc + ":" + m[1]
			if !heard[entry] {
				heard[entry] = true
				vl.Listening = append(vl.Listening, entry)
			}
			if label, ok := knownServers[proc]; ok {
				detected[label] = true
			} else {
				detected[proc] = true
			}
			continue
		}
		if m := reListenPort.FindStringSubmatch(line); len(m) == 2 {
			entry := ":" + m[1]
			if !heard[entry] {
				heard[entry] = true
				vl.Listening = append(vl.Listening, entry)
			}
		}
	}

	seen := map[string]bool{}
	addSite := func(name, port string) {
		name = strings.Trim(name, "\"'")
		if name == "" || name == "_" || strings.HasPrefix(name, "*") {
			return
		}
		k := name + "|" + port
		if seen[k] {
			return
		}
		seen[k] = true
		vl.Sites = append(vl.Sites, VHost{Name: name, Port: port})
	}

	// 2) nginx: pair each server_name with the most recent listen port seen in the same dump.
	lastPort := ""
	for _, line := range strings.Split(sec["nginx"], "\n") {
		if m := reNginxListen.FindStringSubmatch(line); len(m) == 2 {
			lastPort = m[1]
			continue
		}
		if m := reNginxName.FindStringSubmatch(line); len(m) == 2 {
			for _, name := range strings.Fields(strings.TrimRight(m[1], ";")) {
				addSite(name, lastPort)
			}
		}
	}
	// 3) apache: "port <p> namevhost <name>".
	for _, line := range strings.Split(sec["apache"], "\n") {
		if m := reApacheNamevh.FindStringSubmatch(line); len(m) == 3 {
			addSite(m[2], m[1])
		}
	}
	// 4) caddy: site-block address lines ("example.com {").
	for _, line := range strings.Split(sec["caddy"], "\n") {
		if m := reCaddySite.FindStringSubmatch(line); len(m) == 2 {
			addr := m[1]
			port := "80"
			if strings.HasPrefix(addr, ":") {
				port = strings.TrimPrefix(addr, ":")
			} else if strings.HasPrefix(addr, "[") {
				port = "443"
			}
			addSite(addr, port)
		}
	}

	// 5) Decide the reported Server.
	switch {
	case len(vl.Sites) > 0 && detected["nginx"]:
		vl.Server = "nginx"
	case len(vl.Sites) > 0 && detected["apache"]:
		vl.Server = "apache"
	case len(vl.Sites) > 0 && detected["caddy"]:
		vl.Server = "caddy"
	case len(detected) > 0:
		for label := range detected {
			vl.Server = label
			break
		}
	case len(vl.Listening) > 0:
		// Web ports are open but we could not identify the process (typical for a non-root SSH user
		// without sudo). Surface "unknown" rather than a misleading "none".
		vl.Server = "unknown"
	default:
		vl.Server = "none"
	}
	return vl
}
