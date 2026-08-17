//go:build linux

// Package install — Linux-specific local collectors for the host audit (context, ssh, listening
// ports, firewall engines). Build-tagged so the same package cross-compiles to Windows/macOS.
//
// region MODULE_CONTRACT [DOMAIN(8): Security; CONCEPT(8): HostAudit; TECH(7): /proc,/etc,nftables]
// @purpose Provide the Linux implementations of the OS-collector interface used by Audit().
// endregion MODULE_CONTRACT
// GREP_SUMMARY: linux collectors, os-release, proc net tcp, sshd_config, ufw, nftables, iptables
package install

import (
	"context"
	"os"
	"strings"
	"time"
)

// isElevated: on Linux, "elevated" == root (the service should not run as root on a remote host).
func isElevated() bool { return os.Geteuid() == 0 }

// region FUNC_collectContextOS [DOMAIN(6): Posture; CONCEPT(7): HostMeta; TECH(6): /proc,statfs]
// @purpose Gather distro/kernel/uptime/free-disk for sizing and orientation (Linux).
// @complexity 3
// endregion FUNC_collectContextOS
func collectContextOS() HostContext {
	c := HostContext{
		Distro: parseOSRelease("/etc/os-release"),
		Kernel: readTrim("/proc/sys/kernel/ostype") + " " + readTrim("/proc/sys/kernel/osrelease"),
	}
	if up := readField("/proc/uptime", 0); up != "" {
		if secs, err := parseFloat(up); err == nil {
			c.Uptime = (time.Duration(secs) * time.Second).Round(time.Minute).String()
		}
	}
	c.DiskFreeGB = diskFreeGB()
	return c
}

// collectSSHOS reads the sshd posture (Linux only — /etc/ssh/sshd_config).
func collectSSHOS() SSHConfig { return parseSSHDConfig("/etc/ssh/sshd_config") }

// collectPortsOS reads locally-listening TCP sockets from /proc/net/tcp[6].
func collectPortsOS() []PortRow {
	return append(parseListeningPorts("/proc/net/tcp", "tcp"), parseListeningPorts("/proc/net/tcp6", "tcp6")...)
}

// region FUNC_collectFirewallOS [DOMAIN(8): Security; CONCEPT(7): Firewall; TECH(8): exec,nftables]
// @purpose Detect ufw/firewalld/nftables/iptables state + fail2ban. A binary that is present but
// @purpose unreadable (needs root) is "unknown" — NEVER falsely "absent".
// @complexity 5
// endregion FUNC_collectFirewallOS
func collectFirewallOS(ctx context.Context) FirewallState {
	fw := FirewallState{}
	fw.Engines = append(fw.Engines, EngineState{Name: "ufw", State: fwProbe(ctx, "ufw", "status")})
	fw.Engines = append(fw.Engines, EngineState{Name: "firewalld", State: fwProbe(ctx, "firewall-cmd", "--state")})
	// nftables (Ubuntu/Debian default): "nft list ruleset" prints the active ruleset.
	if out, err := runCmd(ctx, 3*time.Second, "nft", "list", "ruleset"); err != nil {
		fw.Engines = append(fw.Engines, EngineState{Name: "nftables", State: stateFromErr(err)})
	} else {
		fw.Engines = append(fw.Engines, EngineState{Name: "nftables", State: nftState(out)})
		fw.Rules += strings.Count(out, "\n")
	}
	// iptables (often the nft backend on modern systems): count -S rules.
	if out, err := runCmd(ctx, 3*time.Second, "iptables", "-S"); err != nil {
		fw.Engines = append(fw.Engines, EngineState{Name: "iptables", State: stateFromErr(err)})
	} else {
		n := strings.Count(out, "\n")
		fw.Rules += n
		st := "empty"
		if n > 0 {
			st = "active"
		}
		fw.Engines = append(fw.Engines, EngineState{Name: "iptables", State: st})
	}
	if out, _ := runCmd(ctx, 3*time.Second, "systemctl", "is-active", "fail2ban"); strings.TrimSpace(out) == "active" {
		fw.Fail2ban = true
	}
	return fw
}

// fwProbe runs a state-printing firewall tool (ufw/firewalld) and maps the result.
func fwProbe(ctx context.Context, name string, args ...string) string {
	out, err := runCmd(ctx, 3*time.Second, name, args...)
	if err != nil {
		return stateFromErr(err)
	}
	out = strings.ToLower(strings.TrimSpace(out))
	switch {
	case strings.Contains(out, "active"), strings.Contains(out, "running"):
		return "active"
	default:
		return "inactive"
	}
}

// stateFromErr maps a probe error to absent (missing binary) or unknown (runtime/permission).
func stateFromErr(err error) string {
	if isNotFound(err) {
		return "absent"
	}
	return "unknown"
}

// nftState classifies `nft list ruleset` output: non-empty => active, empty => empty.
func nftState(out string) string {
	if strings.TrimSpace(out) == "" {
		return "empty"
	}
	return "active"
}
