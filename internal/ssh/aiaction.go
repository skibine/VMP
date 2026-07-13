// Package ssh — execution of operator-approved commands (Plane B mutating actions).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): ExecApproved; TECH(8): ssh]
// @purpose Run a command on a VM over an open SSH client. The command MUST already be approved by
//
//	the operator (or auto-approve) — this is the executor, not the gate. A destructive-pattern
//	backstop refuses catastrophic commands regardless of approval.
//
// @io (ctx, *gossh.Client, command, timeout) -> (output, error)
// @invariants
//   - IsDestructiveCommand blocks rm-of-root / mkfs / dd-to-disk / fork-bomb even if approved.
//   - Output is bounded (truncated) so a runaway command can't OOM the response.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: run command, exec, approved, mutating, destructive, plane b, executor
// STRUCTURE: ▶ ┌client,cmd┐ → 〈IsDestructive? refuse〉 → ⚡ CombinedOutput(bounded) → ⊕ trim → ⎷ string
package ssh

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	gossh "golang.org/x/crypto/ssh"
)

// RunCommand executes an approved command over an open client and returns bounded combined output.
// The caller's ctx bounds the run; on ctx cancellation the remote command is best-effort killed.
func (d *Dialer) RunCommand(ctx context.Context, client *gossh.Client, command string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("empty command")
	}
	if IsDestructiveCommand(command) {
		return "", fmt.Errorf("refused: command matches a destructive pattern (rm -rf /, mkfs, dd to disk, fork bomb)")
	}
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("run-command: new session: %w", err)
	}
	defer sess.Close()

	type result struct {
		out []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		out, err := sess.CombinedOutput(command)
		done <- result{out, err}
	}()
	select {
	case r := <-done:
		out := r.out
		if len(out) > 16*1024 {
			out = append(out[:16*1024], []byte("\n...[truncated]...")...)
		}
		res := strings.TrimSpace(string(out))
		if r.err != nil {
			return res, fmt.Errorf("exit: %w", r.err)
		}
		return res, nil
	case <-ctx.Done():
		_ = sess.Signal(gossh.SIGKILL) // best-effort abort
		return "", ctx.Err()
	}
}

// destructivePatterns are catastrophic commands refused even after operator approval.
var destructivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+-[a-z]*r[a-z]*f?\s+/(\s|$)`), // rm -rf /
	regexp.MustCompile(`(?i)\bmkfs\b`),
	regexp.MustCompile(`(?i)\bdd\b.*\bof=/dev/(sd|nvme|vd|hd|xvd)`),
	regexp.MustCompile(`(?i):\s*\(\s*\)\s*\{`), // fork bomb :(){:|:&};:
	regexp.MustCompile(`(?i)\bshutdown\b.*\bnow\b`),
}

// IsDestructiveCommand reports whether a command matches a catastrophic pattern (hard backstop).
func IsDestructiveCommand(command string) bool {
	for _, re := range destructivePatterns {
		if re.MatchString(command) {
			return true
		}
	}
	return false
}
