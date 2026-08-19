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
//
// sudo handling: the AI executor is non-interactive (no PTY), so a sudo password prompt cannot be
// answered. If the command's first token is `sudo`:
//   - sudoPassword != "" -> rewrite to `sudo -S -p ” <rest>` and feed the password on stdin (one
//     line). This lets the AI install packages / restart services when the operator stored a sudo
//     password for the VM.
//   - sudoPassword == "" -> rewrite to `sudo -n <rest>` (passwordless / NOPASSWD sudoers entry);
//     if a password is actually required, sudo exits non-zero with a clear error.
func (d *Dialer) RunCommand(ctx context.Context, client *gossh.Client, command, sudoPassword string) (string, error) {
	command = strings.TrimSpace(command)
	if command == "" {
		return "", fmt.Errorf("empty command")
	}
	if IsDestructiveCommand(command) {
		return "", fmt.Errorf("refused: command matches a destructive pattern (rm -rf /, mkfs, dd to disk, fork bomb)")
	}
	cmd, stdin := prepareSudo(command, sudoPassword)
	sess, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("run-command: new session: %w", err)
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

// prepareSudo rewrites a `sudo ...` command for non-interactive execution and returns the (command,
// stdin) pair. stdin is the sudo password line when -S is used, empty otherwise. Non-sudo commands
// pass through unchanged. A bare `sudo` with nothing after it is left as-is (no injection).
func prepareSudo(command, sudoPassword string) (string, string) {
	t := strings.TrimSpace(command)
	if t != "sudo" && !strings.HasPrefix(t, "sudo ") {
		return command, ""
	}
	rest := strings.TrimSpace(strings.TrimPrefix(t, "sudo"))
	if rest == "" {
		return command, "" // bare sudo — don't inject (would start an interactive root shell)
	}
	if sudoPassword != "" {
		return "sudo -S -p '' " + rest, sudoPassword + "\n"
	}
	return "sudo -n " + rest, ""
}

// destructivePatterns are catastrophic commands refused even after operator approval.
// BUG_FIX_CONTEXT: now that RunCommand supports `sudo -S` (commands can run as ROOT), the rm
// backstop must block recursive deletes of root AND system directories (/, /home, /etc, ...),
// not just bare `rm -rf /`. Normal cleanups still pass: `rm -rf /home/user/temp` (subpath) and
// `rm /tmp/file` (no -r) are allowed.
// BUG_FIX_CONTEXT (2026-08-19 audit): the old list covered only disk-wipe/fork-bomb class
// payloads. Remote-code-execution exfiltration patterns (curl|bash, /dev/tcp reverse shells,
// eval of fetched content, chmod 777 /) passed freely - and prompt injection via monitored
// pages can request exactly those. Extended to the classic "attacker menu".
var destructivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+-[a-z]*r[a-z]*\s+/(?:home|etc|usr|var|boot|bin|sbin|lib|lib64|root|opt|srv|proc|sys|dev|run)?/?(?:\s|$)`),
	regexp.MustCompile(`(?i)\bmkfs\b`),
	regexp.MustCompile(`(?i)\bdd\b.*\bof=/dev/(sd|nvme|vd|hd|xvd)`),
	regexp.MustCompile(`(?i):\s*\(\s*\)\s*\{`), // fork bomb :(){:|:&};:
	regexp.MustCompile(`(?i)\bshutdown\b.*\bnow\b`),
	// download-and-execute pipelines (curl/wget piped or chained into a shell)
	regexp.MustCompile(`(?i)\b(curl|wget)\b[^|;&]*[|;]\s*(sudo\s+)?(ba|z|da|k)?sh\b`),
	regexp.MustCompile(`(?i)\b(curl|wget)\b.*&&\s*(sudo\s+)?(ba|z|da|k)?sh\b`),
	// eval/exec of variable or fetched content
	regexp.MustCompile(`(?i)\beval\b\s+["'$]`),
	regexp.MustCompile(`(?i)\bbase64\b[^|]*\|\s*(ba|z|da)?sh\b`),
	// reverse shells: /dev/tcp redirect target, bash -i spawned networked, nc -e
	regexp.MustCompile(`/dev/tcp/`),
	regexp.MustCompile(`(?i)\b(ba|z|da|k)?sh\s+-i\b.*(<|>)`),
	regexp.MustCompile(`(?i)\bnc\b[^|]*\s-[a-z]*e[a-z]*\b`),
	regexp.MustCompile(`(?i)\bsocat\b.*\b(ba|z)?sh\b`),
	// permission wholesale + auth tampering
	regexp.MustCompile(`(?i)\bchmod\s+-R\s+777\s+/`), // chmod -R 777 / or /root etc
	regexp.MustCompile(`(?i)\bchmod\s+-R\s+777\s+/(?:root|etc|usr|var|home)(?:\s|/|$)`),
	regexp.MustCompile(`(?i)\brm\s+-[a-z]*f[a-z]*\s+/(?:root/)?\.ssh/authorized_keys`),
	regexp.MustCompile(`(?i)\broot\b.*\b(chpasswd|passwd)\b`),
	regexp.MustCompile(`(?i)\b(chpasswd|passwd)\b.*\broot\b`),
	regexp.MustCompile(`(?i)>\s*/etc/(ssh/)?sshd_config`),
	// BUG_FIX_CONTEXT (audit round 2): prepared-payload bypasses of the first list.
	// process substitution / command substitution feeding a shell from the network
	regexp.MustCompile(`(?i)\b(ba|z|da|k)?sh\s+<\(`),
	regexp.MustCompile(`(?i)\b(ba|z|da|k)?sh\s+-c\s+["'\x60]?\$\(`),
	// fetch piped into ANY scripting interpreter (python/perl/ruby/node joined the sh family)
	regexp.MustCompile(`(?i)\b(curl|wget)\b[^|]*\|\s*(python3?|perl|ruby|node)\b`),
	// two-step download: fetch, make executable, run (covers && and ; chains)
	regexp.MustCompile(`(?i)\b(curl|wget)\b.*&&\s*[^;]*chmod\s+\+x`),
	regexp.MustCompile(`(?i)\b(curl|wget)\b[^;]*;\s*[^;]*chmod\s+\+x`),
	// ncat raw exec mode
	regexp.MustCompile(`(?i)\bncat\b[^|]*--exec\b`),
	// time-based payload delay (test blind RCE)
	regexp.MustCompile(`(?i)\bsleep\b\s+\d{2,}`),
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
