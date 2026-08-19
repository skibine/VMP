//go:build windows

// Package install — Windows-specific local collectors for the host audit: Windows Firewall state
// (netsh advfirewall), listening ports (netstat -ano), Windows version (ver), and admin elevation.
// Build-tagged so the package cross-compiles alongside the Linux collectors.
//
// region MODULE_CONTRACT [DOMAIN(8): Security; CONCEPT(8): HostAudit; TECH(8): netsh,netstat,win32]
// @purpose Provide the Windows implementations of the OS-collector interface used by Audit().
// @purpose The network posture + external exposures are already cross-platform (net + ipwho.is).
// endregion MODULE_CONTRACT
// GREP_SUMMARY: windows collectors, netsh advfirewall, netstat listening, windows-firewall, admin
package install

import (
	"context"
	"os/exec"

	"github.com/skibine/vmp/internal/sysproc"
	"strings"
	"time"
)

// isElevated: on Windows, "elevated" == running as Administrator. `net session` succeeds only with
// admin rights, so a zero-exit run is a reliable, dependency-free admin check.
func isElevated() bool {
	cctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, "net", "session")
	sysproc.Attach(cmd) // no console flash on windowsgui builds
	return cmd.Run() == nil
}

// collectContextOS gathers the Windows version label + free disk (uptime is skipped — Windows
// exposes it only via performance counters, not worth the complexity for the audit).
func collectContextOS() HostContext {
	c := HostContext{DiskFreeGB: diskFreeGB()}
	if out, err := runCmd(context.Background(), 3*time.Second, "cmd", "/c", "ver"); err == nil {
		// "Microsoft Windows [Version 10.0.22631.4317]"
		c.Distro = strings.TrimSpace(out)
	}
	return c
}

// collectSSHOS: no sshd_config on Windows (OpenSSH server config, if installed, is non-standard) —
// return empty (the SSH posture finding is Linux-oriented anyway).
func collectSSHOS() SSHConfig { return SSHConfig{} }

// collectPortsOS reads locally-listening TCP sockets via `netstat -ano`.
func collectPortsOS() []PortRow {
	out, err := runCmd(context.Background(), 4*time.Second, "netstat", "-ano")
	if err != nil {
		return nil
	}
	return parseNetstatListening(out)
}

// region FUNC_collectFirewallOS [DOMAIN(8): Security; CONCEPT(7): Firewall; TECH(7): netsh,advfirewall]
// @purpose Read the Windows Firewall state across all profiles (Domain/Private/Public). `netsh
// @purpose advfirewall show allprofiles state` prints a State (ON/OFF) per profile; all-ON => active.
// @complexity 4
// endregion FUNC_collectFirewallOS
func collectFirewallOS(ctx context.Context) FirewallState {
	fw := FirewallState{}
	out, err := runCmd(ctx, 4*time.Second, "netsh", "advfirewall", "show", "allprofiles", "state")
	st := "unknown"
	if err == nil {
		st = parseNetshFirewall(out)
	} else if isNotFound(err) {
		st = "absent" // netsh missing (very unusual on Windows)
	}
	fw.Engines = append(fw.Engines, EngineState{Name: "windows-firewall", State: st})
	return fw
}
