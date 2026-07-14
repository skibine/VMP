// Package ssh — available package updates probe (Debian/Ubuntu apt + RHEL-family dnf). Plane B.
//
// region MODULE_CONTRACT [DOMAIN(8): Observability; CONCEPT(7]: Updates; TECH(8]: ssh,apt]
// @purpose Tell the operator "does this box need updates, and is a reboot pending" — a key health
//
//	signal for a VM. Uses apt-get SIMULATE (no install) so it's read-only and safe.
//
// @io (ctx, *gossh.Client) -> (Updates, error)
// @invariants
//   - The command is a compile-time constant: `apt-get -s upgrade` (simulate, no mutation) + a
//     reboot-required flag check. No user input reaches the shell.
//   - A missing package manager -> Manager="none", Count 0 (not an error).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: updates, upgradable, apt, apt-get, dnf, security, reboot-required, packages, plane b
// STRUCTURE: ▶ ┌client┐ → ⚡ CombinedOutput(FIXED apt-get -s + reboot check) → ◇ parse → ⊕ Updates
package ssh

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// updatesCMD is the fixed, read-only update check (simulate only — never installs).
const updatesCMD = `echo =mgr=; if command -v apt-get >/dev/null 2>&1; then echo apt; elif command -v dnf >/dev/null 2>&1; then echo dnf; else echo none; fi
echo =upd=; apt-get -s upgrade 2>/dev/null | grep -E '^Inst' | head -400
echo =dnf=; dnf check-update -q 2>/dev/null | grep -E '^[a-zA-Z0-9]' | head -400
echo =reboot=; if test -f /var/run/reboot-required 2>/dev/null; then echo yes; else echo no; fi`

// UpdPkg is one upgradable package.
type UpdPkg struct {
	Name     string `json:"name"`
	Version  string `json:"version"`
	Suite    string `json:"suite"`
	Security bool   `json:"security"`
}

// Updates is the parsed update picture.
type Updates struct {
	Manager        string   `json:"manager"` // apt | dnf | none
	Count          int      `json:"count"`
	SecurityCount  int      `json:"security_count"`
	RebootRequired bool     `json:"reboot_required"`
	Packages       []UpdPkg `json:"packages"`
}

// region FUNC_Dialer_Updates [DOMAIN(8): Observability; CONCEPT(7]: Updates; TECH(8]: ssh]
// @purpose Run the read-only update check over an open client and parse upgradable packages.
// @complexity 6
// endregion FUNC_Dialer_Updates
func (d *Dialer) Updates(ctx context.Context, client *gossh.Client) (Updates, error) {
	sess, err := client.NewSession()
	if err != nil {
		return Updates{}, fmt.Errorf("updates: new session: %w", err)
	}
	defer sess.Close()
	out, _ := sess.CombinedOutput(updatesCMD)
	return parseUpdates(string(out)), nil
}

var (
	reAptInst = regexp.MustCompile(`^Inst\s+(\S+)\s+\[(\S+)\]\s+\((\S+)\s+(\S+)`)
	reDnfLine = regexp.MustCompile(`^([a-zA-Z0-9_.+-]+)\s+(\S+)\s+(\S+)`)
)

// parseUpdates extracts the upgradable package list from the sectioned dump (tolerant).
func parseUpdates(out string) Updates {
	sec := splitSections(out)
	u := Updates{Manager: strings.TrimSpace(sec["mgr"]), Packages: []UpdPkg{}}

	// apt: "Inst <name> [<old>] (<new> <suite...>)"
	for _, line := range strings.Split(sec["upd"], "\n") {
		if m := reAptInst.FindStringSubmatch(line); len(m) == 5 {
			name, ver, suite := m[1], m[3], m[4]
			sec := isSecurity(suite)
			u.Packages = append(u.Packages, UpdPkg{Name: name, Version: ver, Suite: suite, Security: sec})
			u.Count++
			if sec {
				u.SecurityCount++
			}
		}
	}
	// dnf fallback: "<name.arch> <ver> <repo>" lines (only if apt yielded nothing and mgr is dnf).
	if u.Count == 0 && u.Manager == "dnf" {
		for _, line := range strings.Split(sec["dnf"], "\n") {
			if m := reDnfLine.FindStringSubmatch(line); len(m) == 4 {
				name := m[1]
				if i := strings.Index(name, "."); i > 0 {
					name = name[:i]
				}
				sec := isSecurity(m[3])
				u.Packages = append(u.Packages, UpdPkg{Name: name, Version: m[2], Suite: m[3], Security: sec})
				u.Count++
				if sec {
					u.SecurityCount++
				}
			}
		}
	}
	if strings.TrimSpace(sec["reboot"]) == "yes" {
		u.RebootRequired = true
	}
	return u
}

// isSecurity reports whether a suite/origin string denotes a security update (heuristic).
func isSecurity(suite string) bool {
	s := strings.ToLower(suite)
	return strings.Contains(s, "security") || strings.Contains(s, "-esm")
}
