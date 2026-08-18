package ssh

import "strings"

import (
	"testing"
)

// region FUNC_test_ParseErrors [DOMAIN(6): Testing; CONCEPT(6): Parsing; TECH(4): regex]
// @purpose Verify journalctl short-iso line parsing and tolerant handling of noise.
// @complexity 2
// endregion FUNC_test_ParseErrors
func TestParseErrors(t *testing.T) {
	raw := `2026-07-13T00:12:34+0000 server-shk systemd-resolved[612]: Server: DNS query failed: connection refused
2026-07-13T00:13:01+0000 server-shk sshd[1234]: Failed password for invalid user admin from 1.2.3.4
2026-07-13T00:14:00+0000 server-shk kernel: BUG: unable to handle page fault at ffff8800
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
	if el.Entries[0].TS != "2026-07-13T00:12:34+0000" {
		t.Errorf("ts wrong: %s", el.Entries[0].TS)
	}
	t.Logf("[IMP:8][TestParseErrors][RESULT] count=%d incl kernel=%s", el.Count, el.Entries[2].Unit)
}

// TestParseErrors_ShortISO verifies the regex matches journalctl -o short-iso output (ISO ts with
// 'T' + tz offset), the format the command actually produces. This was the root cause of "always 0
// errors": the old regex expected a space-separated short-format ts and never matched short-iso.
func TestParseErrors_ShortISO(t *testing.T) {
	in := `2026-07-28T17:59:00+0000 server-frun2d sshd[360412]: error: kex_exchange_identification: Connection closed by remote host
2026-07-28T17:59:30+0000 server-frun2d sshd[360413]: error: PAM authentication failure for user root
-- No entries --
`
	el := parseErrors(in)
	if el.Count != 2 {
		t.Fatalf("want 2 entries, got %d: %+v", el.Count, el)
	}
	if el.Entries[0].Unit != "sshd" {
		t.Errorf("unit[0] want sshd, got %q", el.Entries[0].Unit)
	}
	if el.Entries[0].TS != "2026-07-28T17:59:00+0000" {
		t.Errorf("ts[0] want ISO, got %q", el.Entries[0].TS)
	}
	if !strings.Contains(el.Entries[0].Msg, "kex_exchange_identification") {
		t.Errorf("msg[0] mismatch: %q", el.Entries[0].Msg)
	}
}
