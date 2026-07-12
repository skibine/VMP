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
//   - journalctl may be unavailable or restricted (non-root); that yields Count 0, not an error.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: errors, logs, journalctl, syslog, priority err, recent errors, diagnostics
// STRUCTURE: ▶ ┌client,window┐ → ◇ allowlist(window) → ⚡ CombinedOutput(journalctl) → ⊕ parse → ⎷ ErrorLog
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
// @complexity 5
// endregion FUNC_Dialer_RecentErrors
func (d *Dialer) RecentErrors(ctx context.Context, client *gossh.Client, window string) (ErrorLog, error) {
	since, ok := journalSince[window]
	if !ok {
		since, window = journalSince["24h"], "24h"
	}
	// Fixed command; the only interpolated value comes from the allowlist above.
	cmd := fmt.Sprintf(
		`journalctl -p err --since %q --no-pager -o short-iso 2>/dev/null | tail -100`, since)
	sess, err := client.NewSession()
	if err != nil {
		return ErrorLog{}, fmt.Errorf("recent-errors: new session: %w", err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	if err != nil {
		// journalctl may exit non-zero when there are no matching entries; treat as empty.
		return ErrorLog{Window: window, Count: 0, Entries: []ErrorEntry{}}, nil
	}
	el := parseErrors(string(out))
	el.Window = window
	return el, nil
}

// reErrLine matches "<iso-ts> <host> <unit>[pid]: <message>".
var reErrLine = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\S+\s+(.+?)\[\d+\]:\s*(.*)$`)

// parseErrors extracts structured entries from journalctl short-iso output (tolerant).
func parseErrors(out string) ErrorLog {
	el := ErrorLog{Entries: []ErrorEntry{}}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-- No entries") {
			continue
		}
		if m := reErrLine.FindStringSubmatch(line); len(m) == 4 {
			el.Entries = append(el.Entries, ErrorEntry{TS: m[1], Unit: m[2], Msg: m[3]})
		}
	}
	el.Count = len(el.Entries)
	return el
}
