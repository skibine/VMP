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

	"github.com/skibine/vm-pulse/internal/logging"
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
func (d *Dialer) RecentErrors(ctx context.Context, client *gossh.Client, window, sudoPassword string) (ErrorLog, error) {
	since, ok := journalSince[window]
	if !ok {
		since, window = journalSince["24h"], "24h"
	}
	logging.LDD(d.logger, 7, "RecentErrors", "START", fmt.Sprintf("window=%s sudo_set=%t", window, sudoPassword != ""))
	// NOTE: no `2>/dev/null` — we must SEE permission failures to report them honestly.
	base := fmt.Sprintf(`journalctl -p err --since %q -n 100 --no-pager -o short-iso`, since)

	// When the VM has a stored sudo password, use it authoritatively (sudo -S + password on stdin)
	// so a non-root SSH user with password-sudo can still read the system journal.
	if sudoPassword != "" {
		out, runErr := d.runCaptured(ctx, client, "sudo -S -p '' "+base, sudoPassword+"\n")
		logging.LDD(d.logger, 8, "RecentErrors", "RAW_SUDO_S", fmt.Sprintf("len=%d out=%q err=%v", len(out), snippet(out), runErr))
		el := parseErrors(out)
		if el.Count > 0 {
			logging.LDD(d.logger, 8, "RecentErrors", "RESULT", fmt.Sprintf("count=%d (via sudo -S)", el.Count))
			el.Window = window
			return el, nil
		}
		if isPermDenied(out) {
			logging.LDD(d.logger, 9, "RecentErrors", "NO_ACCESS", "sudo -S denied: "+snippet(out))
			return ErrorLog{}, fmt.Errorf("no journal access — the sudo password is wrong or sudo is unavailable on the VM")
		}
		logging.LDD(d.logger, 8, "RecentErrors", "RESULT", "count=0 (sudo -S ok, genuinely clean)")
		el.Window = window
		return el, nil
	}

	// No stored password: try plain journalctl, fall back to passwordless sudo (sudo -n).
	out, runErr := d.runCaptured(ctx, client, base, "")
	logging.LDD(d.logger, 8, "RecentErrors", "RAW_PLAIN", fmt.Sprintf("len=%d out=%q err=%v", len(out), snippet(out), runErr))
	el := parseErrors(out)
	if el.Count > 0 {
		logging.LDD(d.logger, 8, "RecentErrors", "RESULT", fmt.Sprintf("count=%d (plain)", el.Count))
		el.Window = window
		return el, nil
	}
	if isPermDenied(out) {
		out2, runErr2 := d.runCaptured(ctx, client, "sudo -n "+base, "")
		logging.LDD(d.logger, 8, "RecentErrors", "RAW_SUDO_N", fmt.Sprintf("len=%d out=%q err=%v", len(out2), snippet(out2), runErr2))
		el2 := parseErrors(out2)
		if el2.Count > 0 {
			logging.LDD(d.logger, 8, "RecentErrors", "RESULT", fmt.Sprintf("count=%d (sudo -n)", el2.Count))
			el2.Window = window
			return el2, nil
		}
		if isPermDenied(out2) {
			logging.LDD(d.logger, 9, "RecentErrors", "NO_ACCESS", "plain+sudo -n denied: "+snippet(out2))
			return ErrorLog{}, fmt.Errorf("no journal access — set the VM's sudo password, or grant the SSH user sudo / systemd-journal group")
		}
		logging.LDD(d.logger, 8, "RecentErrors", "RESULT", "count=0 (sudo -n ok, genuinely clean)")
		el2.Window = window
		return el2, nil
	}
	// Plain journalctl ran fine with zero entries -> genuinely clean.
	logging.LDD(d.logger, 8, "RecentErrors", "RESULT", "count=0 (plain ok, genuinely clean)")
	el.Window = window
	return el, nil
}

// snippet returns a single-line, length-bounded preview of raw command output for diagnostics.
func snippet(s string) string {
	s = strings.ReplaceAll(s, "\n", " ⏎ ")
	s = strings.TrimSpace(s)
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

// runCaptured runs a remote command with combined output and a ctx-abort (best-effort SIGKILL).
// stdin (when non-empty) is fed to the command — used to pass the sudo password for `sudo -S`.
func (d *Dialer) runCaptured(ctx context.Context, client *gossh.Client, cmd, stdin string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new session: %w", err)
	}
	defer sess.Close()
	if stdin != "" {
		sess.Stdin = strings.NewReader(stdin)
	}
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
