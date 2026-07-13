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
