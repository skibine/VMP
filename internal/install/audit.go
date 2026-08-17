// Package install — host self-audit orchestrator. Aggregates privilege, host context, network
// posture (incl. remote/local heuristic), listening ports, sshd posture, firewall state, and the
// external exposures of the host's own public IP — then derives a risk verdict (see risk.go).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(9): HostAudit; TECH(8): net,os,monitor-probes]
// @purpose Let `vmpulse doctor` and the future `--setup` wizard assess the host's exposure BEFORE
// @purpose VM Pulse binds to the network — read-only, best-effort, no mutation.
// @io Audit(ctx) -> HostReport (with Verdict)
// @invariants
//   - Audit never writes or persists; collectors only read /proc, /etc, and run read-only probes.
//   - Any single collector failure is swallowed (recorded in a Note), so the report is always whole.
//   - External probes (PortScan/Exposures) run only when a public IP was discovered.
// endregion MODULE_CONTRACT
// GREP_SUMMARY: host audit, doctor, Audit, privilege, network posture, public ip, asn, firewall, risk
// STRUCTURE: ▶ Audit → ○ Privilege+Context+Network+SSH+Firewall+Ports ─┬─ ⊕ PortScan(publicIP) ─┼─ ⊕ Exposures(publicIP) ── ∑ Risk → ⎷ HostReport
package install

import (
	"context"
	"os"
	"os/user"
	"runtime"
	"time"

	"log/slog"

	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/monitor"
)

// Privilege is the effective identity + capability of the running process.
type Privilege struct {
	UID               int    `json:"uid"`
	User              string `json:"user"`
	Root              bool   `json:"root"`               // unix uid==0
	Elevated          bool   `json:"elevated"`           // windows admin / unix root — "service should not run elevated"
	ViaSudo           string `json:"via_sudo"`           // SUDO_USER when invoked through sudo
	CanBindPrivileged bool   `json:"can_bind_privileged"` // can bind ports <1024 (root on Linux)
}

// HostContext is static-ish host metadata for sizing/orientation.
type HostContext struct {
	Distro     string  `json:"distro"`
	Kernel     string  `json:"kernel"`
	Uptime     string  `json:"uptime"`
	DiskFreeGB float64 `json:"disk_free_gb"`
}

// NetworkPosture captures the host's network face and the remote/local heuristic.
type NetworkPosture struct {
	OwnIPs         []string `json:"own_ips"`
	PublicIP       string   `json:"public_ip"`
	ASN            string   `json:"asn"`
	Org            string   `json:"org"`
	ISP            string   `json:"isp"`
	Country        string   `json:"country"`
	IsDatacenter   bool     `json:"is_datacenter"`
	IsLikelyRemote bool     `json:"is_likely_remote"`
	Note           string   `json:"note,omitempty"`
}

// EngineState is one firewall engine's read result. State is one of:
// active | inactive | empty | absent (binary not installed) | unknown (installed but unreadable,
// e.g. needs root/admin). "absent" is only ever set when the binary is genuinely missing — a
// permission failure is "unknown", so the audit never falsely claims "no firewall".
type EngineState struct {
	Name  string `json:"name"`  // ufw | firewalld | nftables | iptables | windows-firewall
	State string `json:"state"` // active|inactive|empty|absent|unknown
}

// FirewallState is best-effort detection of host firewalling + brute-force protection, reported as
// a list of per-engine states (cross-platform: Linux engines + Windows Firewall).
type FirewallState struct {
	Engines  []EngineState `json:"engines"`
	Rules    int           `json:"rules"`     // rule lines seen (iptables+nft) when readable
	Fail2ban bool          `json:"fail2ban"`
	Note     string        `json:"note,omitempty"`
}

// confirmedAbsent reports that EVERY probed engine is genuinely absent (binary missing). Used by
// the risk model so "no firewall" is only flagged when provably true — never on an unreadable state.
func (f FirewallState) confirmedAbsent() bool {
	if len(f.Engines) == 0 {
		return false // nothing probed -> cannot claim "no firewall"
	}
	for _, e := range f.Engines {
		if e.State != "absent" {
			return false
		}
	}
	return true
}

// anyUnknown reports that at least one engine is installed but couldn't be read (needs root/admin).
func (f FirewallState) anyUnknown() bool {
	for _, e := range f.Engines {
		if e.State == "unknown" {
			return true
		}
	}
	return false
}

// HostReport is the full audit result consumed by the printer and the verdict.
type HostReport struct {
	At        time.Time            `json:"at"`
	Platform  string               `json:"platform"` // "linux" / "unsupported"
	Privilege Privilege            `json:"privilege"`
	Context   HostContext          `json:"context"`
	Network   NetworkPosture       `json:"network"`
	SSH       SSHConfig            `json:"ssh"`
	Firewall  FirewallState        `json:"firewall"`
	Ports     []PortRow            `json:"ports"`     // locally listening
	ExtPorts  []monitor.PortStatus `json:"ext_ports"` // externally reachable (own public IP)
	Exposures []monitor.Finding    `json:"exposures"` // unauth service exposures (own public IP)
	Verdict   Verdict              `json:"verdict"`
}

// Audit runs the full read-only host self-audit and returns a report with a risk verdict. Safe to
// call from `vmpulse doctor` and the `--setup` wizard's first step.
//
// region FUNC_Audit [DOMAIN(9): Security; CONCEPT(9): HostAudit; TECH(8): orchestration]
// @purpose Produce a complete host-exposure report (with verdict) before VM Pulse binds to network.
// @uses monitor.LookupIPInfo, monitor.PortScan, monitor.Exposures, local_linux parsers
// @io ctx -> HostReport
// @complexity 6
// endregion FUNC_Audit
func Audit(ctx context.Context, logger *slog.Logger) HostReport {
	rep := HostReport{At: time.Now().UTC(), Platform: platformName()}
	if rep.Platform != "linux" {
		rep.Network.Note = "unsupported platform: local collectors skipped (network/privilege best-effort)"
		logging.LDD(logger, 7, "Audit", "PLATFORM", rep.Platform)
	}

	rep.Privilege = collectPrivilege()
	// OS-specific local collectors (build-tagged): each platform provides its own
	// context/ports/ssh/firewall readers; Audit calls them unconditionally.
	rep.Context = collectContextOS()
	rep.SSH = collectSSHOS()
	rep.Ports = collectPortsOS()
	rep.Firewall = collectFirewallOS(ctx)
	rep.Network = collectNetwork(ctx, logger)

	// External posture only if we resolved a public IP — scanning a private/empty IP is noise.
	if pub := rep.Network.PublicIP; pub != "" {
		done := make(chan struct{})
		go func() {
			rep.ExtPorts = monitor.PortScan(ctx, pub, 8*time.Second)
			close(done)
		}()
		rep.Exposures = monitor.Exposures(ctx, pub, 8*time.Second)
		select {
		case <-done:
		case <-ctx.Done():
		}
		logging.LDD(logger, 8, "Audit", "EXT_PROBED", "scanned public IP "+pub)
	} else {
		logging.LDD(logger, 7, "Audit", "NO_PUBLIC_IP", "skipped external port/exposure scan")
	}

	rep.Verdict = Risk(rep)
	logging.LDD(logger, 9, "Audit", "VERDICT", "severity="+rep.Verdict.Severity+" score="+itoa(rep.Verdict.Score)+" findings="+itoa(len(rep.Verdict.Findings)))
	return rep
}

func platformName() string {
	if runtime.GOOS == "linux" {
		return "linux"
	}
	return runtime.GOOS
}

// region FUNC_collectPrivilege [DOMAIN(7): Security; CONCEPT(8): Privilege; TECH(6): os]
// @purpose Determine the effective identity and whether the process can bind privileged ports —
// @purpose running the service as root on a remote host is a key risk signal.
// @complexity 2
// endregion FUNC_collectPrivilege
func collectPrivilege() Privilege {
	p := Privilege{UID: os.Geteuid(), ViaSudo: os.Getenv("SUDO_USER")}
	if u, err := user.Current(); err == nil {
		p.User = u.Username
	}
	p.Root = p.UID == 0
	// On Linux, binding ports <1024 requires CAP_NET_BIND_SERVICE (root has it by default).
	p.CanBindPrivileged = p.Root
	if runtime.GOOS != "linux" {
		p.CanBindPrivileged = true // macOS/Windows don't enforce the <1024 rule the same way
	}
	p.Elevated = isElevated() // platform-specific: unix root / windows admin token
	return p
}

// region FUNC_collectNetwork [DOMAIN(8): Security; CONCEPT(9): RemoteLocal; TECH(8): net,ipwho.is]
// @purpose Discover the host's own interface IPs and its public IP/ASN, then classify datacenter vs
// @purpose residential (the "is this a VPS in the internet or a home box?" heuristic).
// @complexity 5
// endregion FUNC_collectNetwork
func collectNetwork(ctx context.Context, logger *slog.Logger) NetworkPosture {
	n := NetworkPosture{OwnIPs: ownIPs()}
	info, err := monitor.LookupIPInfo(ctx, "") // empty IP => ipwho.is returns the CALLER's info
	if err != nil || info.IP == "" {
		n.Note = "could not resolve public IP/ASN (offline or geo provider unreachable)"
		logging.LDD(logger, 8, "NetPosture", "NO_PUBLIC", "public IP lookup failed")
		return n
	}
	n.PublicIP = info.IP
	n.ASN, n.Org, n.ISP, n.Country = info.ASN, info.Org, info.ISP, info.Country
	n.IsDatacenter = looksLikeDatacenter(info.Org, info.ISP, info.Domain, info.PTR)
	// Likely remote = datacenter, OR a public (non-RFC1918) IP sits on a local interface.
	n.IsLikelyRemote = n.IsDatacenter || hasPublicOwnIP(n.OwnIPs)
	logging.LDD(logger, 8, "NetPosture", "CLASSIFIED", "ip="+info.IP+" asn="+info.ASN+" datacenter="+boolStr(n.IsDatacenter)+" remote="+boolStr(n.IsLikelyRemote))
	return n
}
