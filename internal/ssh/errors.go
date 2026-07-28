// Package ssh — recent system-log errors (journalctl). One-shot Plane-B probe over an open client.
//
// region MODULE_CONTRACT [DOMAIN(8): Observability; CONCEPT(7): LogErrors; TECH(8): ssh,journalctl]
// @purpose Surface what is currently broken on the box: recent priority=err log lines. A fast
//
//	"why is this VM unhappy" signal, run on demand (not stored as a time series).
//
// @io (ctx, *gossh.Client, window) -> (ErrorLog, error)
// @invariants
//   - The command is built ONLY from a fixed window allowlist (1h/24h/7d) — no user input reaches
//     the shell, so there is no RCE surface.
//   - A non-root SSH user without journal access gets an honest "no journal access" error, NOT a
//     silent zero (the old `2>/dev/null` hid permission failures and reported 0 errors falsely).
//   - Falls back to `sudo -n journalctl` (passwordless sudo / NOPASSWD) when plain journalctl is
//     denied — consistent with the vhosts/docker probes.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: errors, logs, journalctl, syslog, priority err, recent errors, sudo, diagnostics
// STRUCTURE: ▶ ┌client,window┐ → ◇ allowlist(window) → ⚡ journalctl → 〈denied? sudo -n〉 → ⊕ parse → ⎷ ErrorLog
package ssh

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// ErrorEntry is one parsed error log line.
type ErrorEntry struct {
	TS   string `json:"ts"`
	Unit string `json:"unit"`
	Msg  string `json:"msg"`
}

// ErrorLog is the parsed recent-errors result.
type ErrorLog struct {
	Window  string       `json:"window"`
	Count   int          `json:"count"`
	Entries []ErrorEntry `json:"entries"`
}

// journalSince maps a UI range token to a fixed journalctl --since phrase (RCE-safe allowlist).
var journalSince = map[string]string{
	"1h":  "1 hour ago",
	"24h": "24 hours ago",
	"7d":  "7 days ago",
}

// region FUNC_Dialer_RecentErrors [DOMAIN(8): Observability; CONCEPT(7): LogErrors; TECH(8): ssh]
// @purpose Run a fixed journalctl priority=err probe over an open client and parse recent errors.
// Honests about access: if the SSH user cannot read the journal, returns an error instead of a
// silent zero — so the operator knows to grant sudo / systemd-journal, rather than believe the box
// has zero errors.
// @complexity 6
// endregion FUNC_Dialer_RecentErrors
func (d *Dialer) RecentErrors(ctx context.Context, client *gossh.Client, window string) (ErrorLog, error) {
	since, ok := journalSince[window]
	if !ok {
		since, window = journalSince["24h"], "24h"
	}
	// NOTE: no `2>/dev/null` — we must SEE permission failures to report them honestly.
	cmd := fmt.Sprintf(`journalctl -p err --since %q -n 100 --no-pager -o short-iso`, since)

	out, _ := d.runCaptured(ctx, client, cmd)
	el := parseErrors(out)
	if el.Count > 0 {
		el.Window = window
		return el, nil
	}
	// No parseable entries. If the cause is access denial (not a genuinely clean box), try sudo -n.
	if isPermDenied(out) {
		out2, _ := d.runCaptured(ctx, client, "sudo -n "+cmd)
		el2 := parseErrors(out2)
		if el2.Count > 0 {
			el2.Window = window
			return el2, nil
		}
		if isPermDenied(out2) {
			return ErrorLog{}, fmt.Errorf("no journal access — the SSH user needs sudo (NOPASSWD) or membership in the systemd-journal group")
		}
		el2.Window = window
		return el2, nil
	}
	// Plain journalctl ran fine, zero entries -> genuinely clean.
	el.Window = window
	return el, nil
}

// runCaptured runs a remote command with combined output and a ctx-abort (best-effort SIGKILL).
func (d *Dialer) runCaptured(ctx context.Context, client *gossh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := sess.CombinedOutput(cmd)
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		return string(r.out), r.err
	case <-ctx.Done():
		_ = sess.Signal(gossh.SIGKILL)
		return "", ctx.Err()
	}
}

// permSignals are substrings journalctl/shell emit when the user lacks journal access. Matching any
// means "could not read", which we must NOT confuse with "no errors".
var permSignals = []string{
	"permission denied", "access denied", "not permitted", "operation not permitted",
	"failed to query journal", "failed to get journal", "no journal files",
	"insufficient", "not allowed",
}

func isPermDenied(s string) bool {
	low := strings.ToLower(s)
	for _, sig := range permSignals {
		if strings.Contains(low, sig) {
			return true
		}
	}
	return false
}

// reErrLine matches "<iso-ts> <host> <unit>[pid]: <message>" with the [pid] optional, so kernel
// lines ("<iso> <host> kernel: <msg>") and pid-less units are captured too.
var reErrLine = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\S+\s+(.+?)(?:\[\d+\])?:\s*(.*)$`)

// parseErrors extracts structured entries from journalctl short-iso output (tolerant).
func parseErrors(out string) ErrorLog {
	el := ErrorLog{Entries: []ErrorEntry{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-- No entries") || strings.HasPrefix(line, "-- Journal begins") {
			continue
		}
		if m := reErrLine.FindStringSubmatch(line); len(m) == 4 {
			el.Entries = append(el.Entries, ErrorEntry{TS: m[1], Unit: m[2], Msg: m[3]})
		}
	}
	el.Count = len(el.Entries)
	return el
}
