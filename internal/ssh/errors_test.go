package ssh

import (
	"testing"
)

// region FUNC_test_ParseErrors [DOMAIN(6): Testing; CONCEPT(6): Parsing; TECH(4): regex]
// @purpose Verify journalctl short-iso line parsing and tolerant handling of noise.
// @complexity 2
// endregion FUNC_test_ParseErrors
func TestParseErrors(t *testing.T) {
	raw := `2026-07-13 00:12:34 server-shk systemd-resolved[612]: Server: DNS query failed: connection refused
2026-07-13 00:13:01 server-shk sshd[1234]: Failed password for invalid user admin from 1.2.3.4
2026-07-13 00:14:00 server-shk kernel: BUG: unable to handle page fault at ffff8800
-- No entries --
some unstructured noise line`
	el := parseErrors(raw)
	if el.Count != 3 {
		t.Fatalf("expected 3 parsed entries (incl. kernel), got %d", el.Count)
	}
	if el.Entries[0].Unit != "systemd-resolved" {
		t.Errorf("first unit wrong: %s", el.Entries[0].Unit)
	}
	if el.Entries[1].Unit != "sshd" {
		t.Errorf("second unit wrong: %s", el.Entries[1].Unit)
	}
	if el.Entries[2].Unit != "kernel" {
		t.Errorf("kernel line unit wrong: %s", el.Entries[2].Unit)
	}
	if el.Entries[0].TS != "2026-07-13 00:12:34" {
		t.Errorf("ts wrong: %s", el.Entries[0].TS)
	}
	t.Logf("[IMP:8][TestParseErrors][RESULT] count=%d incl kernel=%s", el.Count, el.Entries[2].Unit)
}
