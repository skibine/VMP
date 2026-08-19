// Package install — report rendering for the `vmpulse doctor` CLI: an ANSI-colored human summary
// and the raw JSON marshalling (for `--json` / machine consumption / future wizard integration).
//
// region MODULE_CONTRACT [DOMAIN(6): UI; CONCEPT(7): ReportRender; TECH(6): text/template-free,fmt]
// @purpose Present the host audit verdict + every finding clearly in a terminal, and serialize the
// @purpose full HostReport to JSON.
// @io (HostReport, Writer) -> text ; (HostReport) -> JSON bytes
// @invariants
//   - Plain text output contains NO secrets (only ports, config flags, IP, ASN, distro).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: print, render, doctor report, ansi, json, verdict, findings
package install

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/skibine/vmp/internal/monitor"
)

// severityColor maps a severity to an ANSI color code.
func severityColor(sev string) string {
	switch sev {
	case "critical":
		return "\x1b[31m" // red
	case "warn":
		return "\x1b[33m" // yellow
	case "ok":
		return "\x1b[32m" // green
	}
	return "\x1b[0m"
}

const reset = "\x1b[0m"
const bold = "\x1b[1m"

// WriteText renders the HostReport as an ANSI-colored human summary to w.
func WriteText(w io.Writer, r HostReport) {
	fmt.Fprintf(w, "\n%sVM Pulse — host self-audit%s\n", bold, reset)
	fmt.Fprintf(w, "platform: %s   distro: %s   kernel: %s\n", r.Platform, orDash(r.Context.Distro), orDash(r.Context.Kernel))
	if r.Context.Uptime != "" {
		fmt.Fprintf(w, "uptime: %s   disk free: %.2f GB\n", r.Context.Uptime, r.Context.DiskFreeGB)
	}
	fmt.Fprintf(w, "%sprivilege:%s uid=%d user=%s root=%v via_sudo=%s\n", bold, reset, r.Privilege.UID, orDash(r.Privilege.User), r.Privilege.Root, orDash(r.Privilege.ViaSudo))

	fmt.Fprintf(w, "%snetwork:%s public_ip=%s asn=%s org=%s country=%s\n", bold, reset, orDash(r.Network.PublicIP), orDash(r.Network.ASN), orDash(r.Network.Org), orDash(r.Network.Country))
	fmt.Fprintf(w, "         datacenter=%v  likely_remote=%v\n", r.Network.IsDatacenter, r.Network.IsLikelyRemote)
	if r.Network.Note != "" {
		fmt.Fprintf(w, "         (%s)\n", r.Network.Note)
	}

	fmt.Fprintf(w, "%sssh:%s permit_root_login=%s password_auth=%s port=%s\n", bold, reset, orDash(r.SSH.PermitRootLogin), orDash(r.SSH.PasswordAuth), orDash(r.SSH.Port))
	fmt.Fprintf(w, "%sfirewall:%s %s rules=%d fail2ban=%v\n", bold, reset, engineList(r.Firewall.Engines), r.Firewall.Rules, r.Firewall.Fail2ban)

	if n := len(r.Ports); n > 0 {
		fmt.Fprintf(w, "%slistening ports:%s %s\n", bold, reset, portList(r.Ports))
	}
	if n := len(r.ExtPorts); n > 0 {
		open := extOpenNames(r.ExtPorts)
		fmt.Fprintf(w, "%sexternally open:%s %s\n", bold, reset, strings.Join(open, ", "))
	}
	if n := len(r.Exposures); n > 0 {
		fmt.Fprintf(w, "%sexposures:%s %d unauth service(s) exposed on the public IP\n", bold, reset, n)
		for _, f := range r.Exposures {
			fmt.Fprintf(w, "  • %s — %s\n", f.Title, f.Detail)
		}
	}

	// Verdict.
	fmt.Fprintf(w, "\n%sverdict: %s%s%s  (risk score %d/100)%s\n", bold, severityColor(r.Verdict.Severity), strings.ToUpper(r.Verdict.Severity), reset, r.Verdict.Score, "")
	if len(r.Verdict.Findings) == 0 {
		fmt.Fprintf(w, "no issues found — looks safe to expose VM Pulse here.\n")
	}
	for _, f := range r.Verdict.Findings {
		fmt.Fprintf(w, "  %s[%s]%s %s\n", severityColor(f.Severity), f.Severity, reset, f.Title)
		fmt.Fprintf(w, "      %s\n", f.Detail)
		fmt.Fprintf(w, "      → %s\n", f.Recommendation)
	}
	fmt.Fprintln(w)
}

// MarshalJSONReport returns the full HostReport as indented JSON.
func MarshalJSONReport(r HostReport) ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// orDash returns "—" for empty strings (nicer terminal output).
func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

func portList(ports []PortRow) string {
	if len(ports) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(ports))
	seen := map[int]bool{}
	for _, p := range ports {
		if seen[p.Port] {
			continue
		}
		seen[p.Port] = true
		parts = append(parts, fmt.Sprintf("%d", p.Port))
	}
	return strings.Join(parts, ", ")
}

func extOpenNames(ps []monitor.PortStatus) []string {
	var out []string
	for _, p := range ps {
		if p.Open {
			if p.Service != "" && p.Service != "unknown" {
				out = append(out, fmt.Sprintf("%d/%s", p.Port, p.Service))
			} else {
				out = append(out, fmt.Sprintf("%d", p.Port))
			}
		}
	}
	return out
}

// engineList renders firewall engines as "name=state name=state ...".
func engineList(engines []EngineState) string {
	if len(engines) == 0 {
		return "—"
	}
	parts := make([]string, 0, len(engines))
	for _, e := range engines {
		parts = append(parts, e.Name+"="+e.State)
	}
	return strings.Join(parts, " ")
}
