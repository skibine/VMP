package ssh

import "testing"

// region FUNC_test_ParseUpdates [DOMAIN(7): Testing; CONCEPT(7]: Updates; TECH(5]: regex]
// @purpose Verify apt Inst-line parsing, security detection, and reboot flag.
// @complexity 3
// endregion FUNC_test_ParseUpdates
func TestParseUpdates(t *testing.T) {
	raw := `=mgr=
apt
=upd=
Inst libc6 [2.31-0ubuntu9.9] (2.31-0ubuntu9.16 Ubuntu:22.04:22.04-security)
Inst openssl [1.1.1f-1ubuntu2.20] (1.1.1f-1ubuntu2.21 Ubuntu:22.04:22.04-security)
Inst curl [7.68.0-1ubuntu2.21] (7.68.0-1ubuntu2.22 Ubuntu:22.04:22.04-updates)
=dnf=
=reboot=
yes`
	u := parseUpdates(raw)
	if u.Manager != "apt" {
		t.Fatalf("manager want apt, got %s", u.Manager)
	}
	if u.Count != 3 {
		t.Fatalf("count want 3, got %d", u.Count)
	}
	if u.SecurityCount != 2 {
		t.Fatalf("security count want 2 (libc6+openssl), got %d", u.SecurityCount)
	}
	if !u.Packages[0].Security {
		t.Errorf("libc6 should be flagged security")
	}
	if u.Packages[2].Security {
		t.Errorf("curl (-updates) should NOT be security")
	}
	if !u.RebootRequired {
		t.Errorf("reboot required should be true")
	}
	t.Logf("[IMP:8][TestUpdates][RESULT] mgr=%s count=%d security=%d reboot=%v", u.Manager, u.Count, u.SecurityCount, u.RebootRequired)
}

// region FUNC_test_ParseUpdates_None [DOMAIN(6): Testing; CONCEPT(6]: Branching; TECH(3]: empty]
// @purpose No package manager / no updates -> none/empty, not an error.
// @complexity 2
// endregion FUNC_test_ParseUpdates_None
func TestParseUpdates_None(t *testing.T) {
	u := parseUpdates("=mgr=\nnone\n=upd=\n=dnf=\n=reboot=\nno\n")
	if u.Manager != "none" || u.Count != 0 || u.RebootRequired {
		t.Fatalf("expected none/empty, got %+v", u)
	}
	t.Logf("[IMP:8][TestUpdates][NONE] mgr=%s count=%d", u.Manager, u.Count)
}
