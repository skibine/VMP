//go:build !linux && !windows

// Package install — macOS/BSD local collectors for the host audit. Build-tagged so the package
// cross-compiles to every GoReleaser target (this file covers darwin; in practice the only
// !linux && !windows platform we ship). Best-effort: pf reads need root, netstat is BSD-shaped.
//
// region MODULE_CONTRACT [DOMAIN(8): Security; CONCEPT(8): HostAudit; TECH(7): sw_vers,netstat,pfctl]
// @purpose Provide the macOS implementations of the OS-collector interface used by Audit()
// @purpose (context/ssh/ports/firewall), so `vmpulse doctor` works on darwin too.
// @invariants
//   - A probe that fails for non-"binary missing" reasons reports "unknown", NEVER "absent".
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: macos collectors, darwin, sw_vers, netstat listening, pf, pfctl, root
// STRUCTURE: ▶ ◈isElevated〈euid=0〉 ▸ Context〈sw_vers+uname〉 ▸ SSH〈/etc/ssh/sshd_config〉 ▸ Ports〈netstat -an LISTEN〉 ▸ FW〈pfctl -s info〉
package install

import (
	"context"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// isElevated: on macOS/BSD, "elevated" == root (reading pf state requires it).
func isElevated() bool { return os.Geteuid() == 0 }

// region FUNC_collectContextOS_other [DOMAIN(6): Posture; CONCEPT(7): HostMeta; TECH(6): sw_vers,uname]
// @purpose Gather the macOS product version + kernel (best-effort; uptime counter not exposed simply).
// @complexity 3
// endregion FUNC_collectContextOS_other
func collectContextOS() HostContext {
	c := HostContext{}
	if out, err := runCmd(context.Background(), 3*time.Second, "sw_vers"); err == nil {
		name, ver := "", ""
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if v, ok := strings.CutPrefix(line, "ProductName:"); ok {
				name = strings.TrimSpace(v)
			}
			if v, ok := strings.CutPrefix(line, "ProductVersion:"); ok {
				ver = strings.TrimSpace(v)
			}
		}
		c.Distro = strings.TrimSpace(name + " " + ver)
	}
	if out, err := runCmd(context.Background(), 3*time.Second, "uname", "-sr"); err == nil {
		c.Kernel = strings.TrimSpace(out)
	}
	c.DiskFreeGB = diskFreeGB()
	return c
}

// collectSSHOS reads the sshd posture (macOS ships /etc/ssh/sshd_config).
func collectSSHOS() SSHConfig { return parseSSHDConfig("/etc/ssh/sshd_config") }

// region FUNC_collectPortsOS_other [DOMAIN(7): Security; CONCEPT(8): OpenPorts; TECH(7): netstat]
// @purpose Read locally-listening TCP sockets from BSD-style `netstat -an` output.
// @complexity 4
// endregion FUNC_collectPortsOS_other
func collectPortsOS() []PortRow {
	out, err := runCmd(context.Background(), 4*time.Second, "netstat", "-an")
	if err != nil {
		return nil
	}
	return parseBSDNetstatListening(out)
}

// parseBSDNetstatListening extracts LISTEN rows from BSD-style netstat output, e.g.
// "tcp4  0  0  127.0.0.1.6379  *.*  LISTEN" or "tcp6  0  0  *.8443  *.*  LISTEN".
// The local address uses dots before the port; "*" means all interfaces.
func parseBSDNetstatListening(out string) []PortRow {
	seen := map[int]bool{}
	var rows []PortRow
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !strings.HasPrefix(f[0], "tcp") || f[len(f)-1] != "LISTEN" {
			continue
		}
		local := f[3]
		i := strings.LastIndex(local, ".")
		if i <= 0 {
			continue
		}
		host, portStr := local[:i], local[i+1:]
		port, err := strconv.Atoi(portStr)
		if err != nil || port <= 0 || seen[port] {
			continue
		}
		seen[port] = true
		addr := host
		switch host {
		case "*":
			addr = "0.0.0.0"
			if f[0] == "tcp6" {
				addr = "::"
			}
		}
		rows = append(rows, PortRow{Port: port, Proto: "tcp", Addr: addr})
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].Port < rows[b].Port })
	return rows
}

// region FUNC_collectFirewallOS_other [DOMAIN(8): Security; CONCEPT(7): Firewall; TECH(7): pfctl]
// @purpose Detect the macOS packet filter (pf) state via `pfctl -s info`. Reading pf requires root,
// @purpose so an unprivileged run reports "unknown" — NEVER falsely "absent" (matches Linux rule).
// @complexity 3
// endregion FUNC_collectFirewallOS_other
func collectFirewallOS(ctx context.Context) FirewallState {
	fw := FirewallState{}
	out, err := runCmd(ctx, 3*time.Second, "pfctl", "-s", "info")
	st := "unknown"
	switch {
	case err != nil && isNotFound(err):
		st = "absent" // pfctl missing (very unusual on macOS)
	case err == nil:
		if strings.Contains(out, "Status: Enabled") {
			st = "active"
		} else {
			st = "inactive"
		}
	}
	fw.Engines = append(fw.Engines, EngineState{Name: "pf", State: st})
	return fw
}
