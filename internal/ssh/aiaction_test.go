package ssh

import "testing"

// region FUNC_test_IsDestructiveCommand [DOMAIN(7): Testing; CONCEPT(7]: Safety; TECH(3]: regex]
// @purpose Verify the destructive-command backstop blocks catastrophic patterns and allows normal ones.
// @complexity 2
// endregion FUNC_test_IsDestructiveCommand
func TestIsDestructiveCommand(t *testing.T) {
	blocked := []string{
		"rm -rf /",
		"sudo rm -rf /home",
		"rm -fr /",
		"mkfs.ext4 /dev/sda1",
		"dd if=/dev/zero of=/dev/sda bs=1M",
		":(){ :|:& };:",
		"shutdown -h now",
	}
	allowed := []string{
		"systemctl restart nginx",
		"docker ps",
		"rm /tmp/old.log",
		"df -h",
		"apt update && apt upgrade -y",
		"journalctl -u ssh --since '1 hour ago' | tail -20",
	}
	for _, c := range blocked {
		if !IsDestructiveCommand(c) {
			t.Errorf("expected destructive block for %q", c)
		}
	}
	for _, c := range allowed {
		if IsDestructiveCommand(c) {
			t.Errorf("expected allowed for %q", c)
		}
	}
	t.Logf("[IMP:8][TestDestructive][RESULT] blocked=%d allowed=%d", len(blocked), len(allowed))
}

// TestPrepareSudo verifies the non-interactive sudo rewrite: with a password -> `sudo -S -p ”`
// + password on stdin; without -> `sudo -n`; non-sudo and bare sudo pass through untouched.
func TestPrepareSudo(t *testing.T) {
	cases := []struct {
		cmd, pw, wantCmd, wantStdin string
	}{
		{"sudo apt install -y traceroute", "s3cr3t", "sudo -S -p '' apt install -y traceroute", "s3cr3t\n"},
		{"  sudo systemctl restart nginx ", "p", "sudo -S -p '' systemctl restart nginx", "p\n"},
		{"sudo -u root whoami", "pw", "sudo -S -p '' -u root whoami", "pw\n"},
		{"sudo apt update", "", "sudo -n apt update", ""},  // no password -> passwordless
		{"apt update", "pw", "apt update", ""},             // not sudo -> untouched
		{"ls -la", "", "ls -la", ""},                       // plain command
		{"sudo", "pw", "sudo", ""},                         // bare sudo -> no injection
		{"cat /etc/sudoers", "pw", "cat /etc/sudoers", ""}, // "sudo" substring, not token
	}
	for _, c := range cases {
		gotCmd, gotStdin := prepareSudo(c.cmd, c.pw)
		if gotCmd != c.wantCmd || gotStdin != c.wantStdin {
			t.Errorf("prepareSudo(%q,%q):\n  cmd   got %q want %q\n  stdin got %q want %q",
				c.cmd, c.pw, gotCmd, c.wantCmd, gotStdin, c.wantStdin)
		}
	}
}
