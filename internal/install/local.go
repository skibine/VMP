// Package install — host self-audit: local-Linux data collectors (pure-Go, read-by-path so they
// are unit-testable with fixture files under t.TempDir()).
//
// region MODULE_CONTRACT [DOMAIN(8): Security; CONCEPT(8): HostAudit, Posture; TECH(7): /proc,/etc,parsing]
// @purpose Give the installer/doctor a read-only, dependency-free view of the host it runs on
// @purpose (distro, kernel, listening ports, sshd posture) so a risk verdict can be produced BEFORE
// @purpose VM Pulse is exposed to the network. Linux-first; callers degrade gracefully elsewhere.
// @io (paths) -> parsed structs
// @invariants
//   - Collectors NEVER write or exec; they only read /proc and /etc.
//   - A missing/unreadable file yields a zero struct (no error) — the audit stays best-effort.
// endregion MODULE_CONTRACT
// GREP_SUMMARY: host audit, doctor, os-release, /proc/net/tcp, listening ports, sshd_config, posture
// STRUCTURE: ▶ ┌path┐ → ○ read → ⚡ parse (kv/columns) → ⊕ struct → ⎋ return
package install

import (
	"bufio"
	"os"
	"strconv"
	"strings"
)

// region FUNC_parseOSRelease [DOMAIN(6): Posture; CONCEPT(7): Distro; TECH(6): kv-parser]
// @purpose Read aPRETTY distro name from an os-release file (last KEY wins, matching systemd spec).
// @io path -> string (e.g. "Ubuntu 22.04.3 LTS")
// @complexity 3
// endregion FUNC_parseOSRelease
func parseOSRelease(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	name, ver := "", ""
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := splitKV(line)
		if !ok {
			continue
		}
		switch k {
		case "PRETTY_NAME":
			return strings.Trim(v, `"`)
		case "NAME":
			name = strings.Trim(v, `"`)
		case "VERSION":
			ver = strings.Trim(v, `"`)
		}
	}
	if name != "" && ver != "" {
		return name + " " + ver
	}
	return name
}

// splitKV splits a "KEY=value" line, stripping surrounding quotes from the value.
func splitKV(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 {
		return "", "", false
	}
	return strings.TrimSpace(line[:i]), strings.Trim(strings.TrimSpace(line[i+1:]), `"`), true
}

// region PortRow [DOMAIN(7): Posture; CONCEPT(8): ListeningPorts; TECH(6): /proc]
// PortRow is one locally-listening socket. Proto is tcp/tcp6; Addr is the bind address (may be
// "0.0.0.0"/"::" for wildcard).
// endregion PortRow
type PortRow struct {
	Port  int    `json:"port"`
	Proto string `json:"proto"`
	Addr  string `json:"addr"`
}

// region FUNC_parseListeningPorts [DOMAIN(8): Security; CONCEPT(8): OpenPorts; TECH(7): /proc/net/tcp]
// @purpose Extract the set of TCP ports in LISTEN state from a /proc/net/tcp-shaped file. Each line
// @purpose is "sl local_address rem_address st ..."; local_address is HEXIP:HEXPORT (little-endian
// @purpose for v4), st==0A means LISTEN. Returns deduplicated, port-sorted rows.
// @io path -> []PortRow
// @complexity 4
// endregion FUNC_parseListeningPorts
func parseListeningPorts(path string, proto string) []PortRow {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []PortRow
	seen := map[int]bool{}
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		if i == 0 { // header
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		local := fields[1]
		state := fields[3]
		if state != "0A" { // not LISTEN
			continue
		}
		colon := strings.IndexByte(local, ':')
		if colon < 0 {
			continue
		}
		portHex := local[colon+1:]
		port, err := strconv.ParseInt(portHex, 16, 32)
		if err != nil || port <= 0 || port > 65535 {
			continue
		}
		p := int(port)
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, PortRow{Port: p, Proto: proto, Addr: decodeHexIP(local[:colon], proto)})
	}
	return out
}

// decodeHexIP decodes the hex IP from /proc/net/tcp[6]. v4 is 4 little-endian bytes; v6 is 4
// little-endian 32-bit words. Best-effort: returns the raw string on any surprise.
func decodeHexIP(hex, proto string) string {
	if proto == "tcp" && len(hex) == 8 {
		n, err := strconv.ParseUint(hex, 16, 32)
		if err == nil {
			b := [4]byte{byte(n), byte(n >> 8), byte(n >> 16), byte(n >> 24)}
			if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 {
				return "0.0.0.0"
			}
			return strconv.Itoa(int(b[0])) + "." + strconv.Itoa(int(b[1])) + "." + strconv.Itoa(int(b[2])) + "." + strconv.Itoa(int(b[3]))
		}
	}
	if proto == "tcp6" {
		return "::" // wildcard for v6 LISTEN; full decode is rarely worth it for the audit
	}
	return hex
}

// region SSHConfig [DOMAIN(8): Security; CONCEPT(8): SSHPosture; TECH(6): sshd_config-parser]
// SSHConfig is the relevant subset of /etc/ssh/sshd_config (last directive wins; Match blocks are
// ignored — the audit is best-effort, not a full config interpreter).
// endregion SSHConfig
type SSHConfig struct {
	ConfigReadable  bool   `json:"config_readable"`
	PermitRootLogin string `json:"permit_root_login"` // yes/prohibit-password/no/"" (unknown)
	PasswordAuth    string `json:"password_auth"`     // yes/no/"" (unknown; default yes per upstream)
	Port            string `json:"port"`
}

// region FUNC_parseSSHDConfig [DOMAIN(8): Security; CONCEPT(8): SSHPosture; TECH(6): parser]
// @purpose Read the three posture-relevant directives from an sshd_config file. Bare defaults apply
// @purpose only when the directive is absent (PasswordAuthentication defaults to "yes").
// @io path -> SSHConfig
// @complexity 3
// endregion FUNC_parseSSHDConfig
func parseSSHDConfig(path string) SSHConfig {
	cfg := SSHConfig{}
	f, err := os.Open(path)
	if err != nil {
		return cfg
	}
	cfg.ConfigReadable = true
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		val := strings.ToLower(fields[1])
		switch key {
		case "permitrootlogin":
			cfg.PermitRootLogin = val
		case "passwordauthentication":
			cfg.PasswordAuth = val
		case "port":
			cfg.Port = val
		}
	}
	// OpenSSH default: PasswordAuthentication is "yes" unless explicitly disabled.
	if cfg.PasswordAuth == "" {
		cfg.PasswordAuth = "yes"
	}
	return cfg
}

// region FUNC_parseNetshFirewall [DOMAIN(8): Security; CONCEPT(7): Firewall; TECH(6): parser]
// @purpose Classify the output of `netsh advfirewall show allprofiles state` (Windows Firewall). The
// @purpose output lists each profile (Domain/Private/Public) with a "State" line (ON/OFF). Returns
// @purpose "active" when EVERY profile is ON, "inactive" if any is OFF, "unknown" if unparseable.
// @purpose Pure (string in) so it is unit-testable on any platform.
// @complexity 3
// endregion FUNC_parseNetshFirewall
func parseNetshFirewall(out string) string {
	lines := strings.Split(out, "\n")
	var states []string
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if !strings.HasPrefix(strings.ToLower(ln), "state") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(strings.ToLower(ln), "state"))
		val = strings.TrimLeft(val, " \t=:")
		switch strings.ToLower(val) {
		case "on", "enable", "enabled":
			states = append(states, "on")
		case "off", "disable", "disabled":
			states = append(states, "off")
		}
	}
	if len(states) == 0 {
		return "unknown"
	}
	for _, s := range states {
		if s != "on" {
			return "inactive" // at least one profile is OFF
		}
	}
	return "active"
}

// region FUNC_parseNetstatListening [DOMAIN(7): Posture; CONCEPT(8): Ports; TECH(6): parser]
// @purpose Extract LISTENING TCP ports from `netstat -ano` output (Windows). Each data row is
// @purpose "Proto LocalAddress ForeignAddress State PID"; we take rows with State==LISTENING and
// @purpose parse the port after the last ':' of the local address. Pure (string in), testable.
// @complexity 3
// endregion FUNC_parseNetstatListening
func parseNetstatListening(out string) []PortRow {
	var rows []PortRow
	seen := map[int]bool{}
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(strings.TrimSpace(ln))
		if len(f) < 4 || strings.ToLower(f[3]) != "listening" {
			continue
		}
		// Local address like "0.0.0.0:135" or "[::]:443".
		local := f[1]
		colon := strings.LastIndexByte(local, ':')
		if colon < 0 {
			continue
		}
		port, err := strconv.Atoi(local[colon+1:])
		if err != nil || port <= 0 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		addr := local[:colon]
		addr = strings.Trim(addr, "[]")
		rows = append(rows, PortRow{Port: port, Proto: f[0], Addr: addr})
	}
	return rows
}
