// Package install — risk model: a PURE function over the collected HostReport that derives a
// severity, a 0–100 score, and a list of findings (title + recommendation). Kept pure so it is
// trivially unit-testable with synthetic reports.
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(9): RiskModel; TECH(6): pure-fn]
// @purpose Turn the raw host posture into an actionable verdict: is it safe to expose VM Pulse here,
// @purpose and if not, exactly what to fix. Severity is dominated by the worst finding (critical wins).
// @io HostReport -> Verdict
// @invariants
//   - Risk NEVER performs IO; it reads only the supplied report.
//   - A critical finding always yields severity "critical", regardless of score.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: risk, verdict, severity, score, findings, recommendations, datacenter, root, firewall
package install

import (
	"sort"

	"github.com/skibine/vmp/internal/monitor"
)

// Verdict is the audit's bottom line.
type Verdict struct {
	Severity string        `json:"severity"` // ok | warn | critical
	Score    int           `json:"score"`    // 0–100, higher = riskier
	Findings []RiskFinding `json:"findings"`
}

// RiskFinding is one issue + its fix.
type RiskFinding struct {
	ID             string `json:"id"`
	Severity       string `json:"severity"` // critical | warn | minor
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation"`
}

// region FUNC_Risk [DOMAIN(9): Security; CONCEPT(9): RiskModel; TECH(6): pure]
// @purpose Derive the host's risk verdict from the collected posture. Critical findings dominate;
// @purpose datacenter/remote posture escalates privilege and firewall findings.
// @complexity 5
// endregion FUNC_Risk
func Risk(r HostReport) Verdict {
	var v Verdict
	remote := r.Network.IsLikelyRemote
	add := func(id, sev, title, detail, rec string) {
		v.Findings = append(v.Findings, RiskFinding{ID: id, Severity: sev, Title: title, Detail: detail, Recommendation: rec})
		switch sev {
		case "critical":
			v.Score += 40
		case "warn":
			v.Score += 15
		default:
			v.Score += 5
		}
	}

	// Service privilege — running the app as root/admin.
	if r.Privilege.Root || r.Privilege.Elevated {
		sev := "warn"
		if remote {
			sev = "critical"
		}
		who := "root"
		if r.Privilege.Elevated && !r.Privilege.Root {
			who = "admin/elevated"
		}
		add("svc_as_root", sev, "process running "+who,
			"uid="+itoa(r.Privilege.UID)+" user="+r.Privilege.User,
			"create an unprivileged system user (e.g. 'vmpulse') and run the service as it.")
	}

	// Unauthenticated service exposures on the public IP (redis/docker API/mongo…).
	if n := len(r.Exposures); n > 0 {
		titles := findingTitles(r.Exposures)
		add("exposed_unauth", "critical", "exposed unauthenticated services",
			joinTitles(titles), "close the port or enable authentication; never expose DB/docker API to the internet.")
	}

	// No firewall on an internet-facing host — ONLY when provably absent (every engine's binary is
	// missing). An unreadable engine (needs root) is "unknown", not "absent", so we never cry wolf.
	if remote && r.Firewall.confirmedAbsent() {
		add("no_firewall_public", "critical", "no host firewall detected",
			"ufw/firewalld/nftables/iptables all absent on a remote host",
			"enable a firewall (ufw) and allow only the ports VM Pulse needs.")
	}
	// Couldn't read the firewall state (needs root/admin) — don't claim it's safe, point to elevation.
	if remote && !(r.Privilege.Root || r.Privilege.Elevated) && r.Firewall.anyUnknown() {
		add("firewall_unreadable", "minor", "firewall state unreadable",
			"one or more firewall engines are installed but returned permission-denied",
			"re-run as an administrator (sudo vmpulse doctor / elevated) to read the firewall state accurately.")
	}

	// SSH posture on a remote host.
	if remote {
		if r.SSH.PasswordAuth == "yes" {
			add("ssh_password_public", "warn", "SSH accepts passwords",
				"PasswordAuthentication=yes on an internet-facing host",
				"use key-based auth and set PasswordAuthentication no.")
		}
		if rl := r.SSH.PermitRootLogin; rl == "yes" || rl == "without-password" || rl == "prohibit-password" {
			add("ssh_root_login", "warn", "SSH permits root login",
				"PermitRootLogin="+rl,
				"set PermitRootLogin no and sudo from a normal account.")
		}
	}

	// Remote/datacenter but planning to bind 0.0.0.0 — the app would be directly internet-exposed.
	if r.Network.IsDatacenter {
		add("datacenter_bind_wildcard", "warn", "hosting/datacenter detected",
			"ASN org="+r.Network.Org+"; exposing VM Pulse's admin UI to the public internet is risky",
			"bind to localhost and reach it over a VPN (Tailscale/WireGuard), or put it behind a reverse proxy + auth/TLS.")
	}

	// Public SSH without fail2ban (brute-force protection).
	if remote && r.Firewall.Fail2ban == false && sshListens(r.Ports) {
		add("no_fail2ban_public_ssh", "minor", "no fail2ban with public SSH",
			"SSH is reachable from the internet but no fail2ban detected",
			"install fail2ban to throttle SSH brute-force attempts.")
	}

	// Disk space.
	if r.Context.DiskFreeGB > 0 && r.Context.DiskFreeGB < 2 {
		add("low_disk", "warn", "low disk space",
			itoa(int(r.Context.DiskFreeGB*100))+" GB free on /",
			"free or expand storage before installing.")
	}

	// Clamp + severity.
	if v.Score > 100 {
		v.Score = 100
	}
	v.Severity = "ok"
	for _, f := range v.Findings {
		if f.Severity == "critical" {
			v.Severity = "critical"
			break
		}
	}
	if v.Severity != "critical" && (v.Score >= 20 || hasSev(v.Findings, "warn")) {
		v.Severity = "warn"
	}
	// Stable order: critical, warn, minor.
	sort.SliceStable(v.Findings, func(i, j int) bool { return sevRank(v.Findings[i].Severity) > sevRank(v.Findings[j].Severity) })
	return v
}

func hasSev(fs []RiskFinding, sev string) bool {
	for _, f := range fs {
		if f.Severity == sev {
			return true
		}
	}
	return false
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "warn":
		return 2
	case "minor":
		return 1
	}
	return 0
}

// sshListens reports whether the host has a TCP listener on 22.
func sshListens(ports []PortRow) bool {
	for _, p := range ports {
		if p.Port == 22 {
			return true
		}
	}
	return false
}

func findingTitles(fs []monitor.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Title)
	}
	return out
}
func joinTitles(ts []string) string {
	if len(ts) == 0 {
		return ""
	}
	out := ts[0]
	for _, t := range ts[1:] {
		out += ", " + t
	}
	return out
}
