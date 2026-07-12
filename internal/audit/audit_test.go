// region MODULE_CONTRACT_test [DOMAIN(9): Testing; CONCEPT(9): TamperEvidence; TECH(8): go test]
// @purpose Verify the audit prev_hash chain: intact after appends, broken after tampering.
//
//	Prints [IMP:7-10] lines (the [IMP:9] APPENDED line is the Semantic Trace anchor).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, audit, tamper, prev_hash, sha256, chain, integrity
// STRUCTURE: ▶ ┌store┐ → ⊕ Append×N → ○ VerifyChain(ok) → ⚡ UPDATE hack → 〈VerifyChain? err〉 → ⎋ assert
package audit

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/lddcheck"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

func openStore(t *testing.T) (*store.Store, *slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := logging.Setup(slog.LevelDebug, &buf)
	dbPath := filepath.Join(t.TempDir(), "audit.sqlite")
	s, err := store.Open(dbPath, logger)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, logger, &buf
}

func printIMPFromBuf(t *testing.T, buf *bytes.Buffer) {
	t.Helper()
	out := buf.String()
	t.Log("--- LDD TRAJECTORY (IMP:7-10) ---")
	saw9 := false
	for _, line := range strings.Split(out, "\n") {
		imp, ok := lddcheck.IMPValue(line)
		if ok && imp >= 7 {
			t.Log(line)
			if imp >= 9 {
				saw9 = true
			}
		}
	}
	if !saw9 {
		t.Errorf("Anti-Illusion: no [IMP:9] APPENDED line captured (Semantic Trace missing)")
	}
}

func TestChain_IntactAfterAppends(t *testing.T) {
	s, logger, buf := openStore(t)
	entries := []Entry{
		{Action: "service.start", Detail: `{"mode":"local"}`, Plane: PlaneA, Success: true},
		{Action: "probe.ping", Detail: `{"vm":1,"ok":true}`, Plane: PlaneA, Success: true},
		{Action: "ssh.open", Detail: `{"vm":2}`, Plane: PlaneB, Success: true},
	}
	for _, e := range entries {
		if err := Append(s.DB, logger, e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	printIMPFromBuf(t, buf)
	if err := VerifyChain(s.DB); err != nil {
		t.Fatalf("chain should be intact, got: %v", err)
	}
}

func TestChain_DetectsTampering(t *testing.T) {
	s, logger, _ := openStore(t)
	_ = Append(s.DB, logger, Entry{Action: "a", Plane: PlaneA})
	_ = Append(s.DB, logger, Entry{Action: "b", Plane: PlaneA})
	if err := VerifyChain(s.DB); err != nil {
		t.Fatalf("precondition: chain must be intact, got %v", err)
	}
	// Mutate the first row's action WITHOUT recomputing its hash -> chain must break.
	if _, err := s.DB.Exec(`UPDATE audit_log SET action='hacked' WHERE id=1`); err != nil {
		t.Fatalf("tamper update: %v", err)
	}
	err := VerifyChain(s.DB)
	if err == nil {
		t.Fatal("VerifyChain must report tampering, got nil")
	}
	if !strings.Contains(err.Error(), "tamper detected") {
		t.Fatalf("unexpected error text: %v", err)
	}
}
