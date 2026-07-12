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

// vhostCMD is the fixed web-server config dump. Section markers make parsing robust.
const vhostCMD = `echo =nginx=; nginx -T 2>/dev/null | grep -iE '^[[:space:]]*(server_name|listen)[[:space:]]' | head -300
echo =apache=; (apache2ctl -S 2>/dev/null || apachectl -S 2>/dev/null) | grep -iE 'namevhost|^[[:space:]]*Server name:' | head -200`

// VHost is one discovered site.
type VHost struct {
	Name string `json:"name"`
	Port string `json:"port"`
}

// VHostList is the parsed web-server vhost picture.
type VHostList struct {
	Server string  `json:"server"` // nginx | apache | none
	Sites  []VHost `json:"sites"`
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
	reNginxListen  = regexp.MustCompile(`(?i)^\s*listen\s+([0-9]+)`)
	reNginxName    = regexp.MustCompile(`(?i)^\s*server_name\s+(.+?);`)
	reApacheNamevh = regexp.MustCompile(`(?i)port\s+(\d+)\s+namevhost\s+(\S+)`)
)

// parseVHosts extracts sites from the sectioned nginx/apache dump (tolerant).
func parseVHosts(out string) VHostList {
	sec := splitSections(out)
	vl := VHostList{Server: "none", Sites: []VHost{}}

	// nginx: pair each server_name with the most recent listen port seen in the same dump.
	seen := map[string]bool{}
	lastPort := ""
	for _, line := range strings.Split(sec["nginx"], "\n") {
		if m := reNginxListen.FindStringSubmatch(line); len(m) == 2 {
			lastPort = m[1]
			continue
		}
		if m := reNginxName.FindStringSubmatch(line); len(m) == 2 {
			for _, name := range strings.Fields(strings.TrimRight(m[1], ";")) {
				name = strings.Trim(name, "\"'")
				if name == "" || name == "_" || strings.HasPrefix(name, "*") {
					continue // skip catch-all / wildcard
				}
				if seen[name+"|"+lastPort] {
					continue
				}
				seen[name+"|"+lastPort] = true
				if vl.Server == "none" {
					vl.Server = "nginx"
				}
				vl.Sites = append(vl.Sites, VHost{Name: name, Port: lastPort})
			}
		}
	}

	// apache: "port <p> namevhost <name>".
	for _, line := range strings.Split(sec["apache"], "\n") {
		if m := reApacheNamevh.FindStringSubmatch(line); len(m) == 3 {
			name := strings.Trim(m[2], "\"'")
			if name == "" || seen[name+"|"+m[1]] {
				continue
			}
			seen[name+"|"+m[1]] = true
			if vl.Server == "none" {
				vl.Server = "apache"
			}
			vl.Sites = append(vl.Sites, VHost{Name: name, Port: m[1]})
		}
	}
	return vl
}
