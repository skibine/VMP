// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): Storage; TECH(8): go test,sqlite]
// @purpose Verify store.Open in a TempDir: migrations applied, schema_versions >= 1,
//
//	audit_log table exists. Prints [IMP:7-10] lines.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, store, sqlite, migrations, schema_versions, wal
// STRUCTURE: ▶ ┌tmpDir┐ → ○ Open → ⚡ migrate → 〈version>=1? audit_log exists?〉 → ⎋ assert
package store

import (
	"bytes"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/lddcheck"
	"github.com/skibine/vm-pulse/internal/logging"
)

func testLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return logging.Setup(slog.LevelDebug, &buf), &buf
}

func printIMPFromBuf(t *testing.T, buf *bytes.Buffer) {
	t.Helper()
	out := buf.String()
	t.Log("--- LDD TRAJECTORY (IMP:7-10) ---")
	for _, line := range strings.Split(out, "\n") {
		if imp, ok := lddcheck.IMPValue(line); ok && imp >= 7 {
			t.Log(line)
		}
	}
}

func TestOpen_AppliesMigrations(t *testing.T) {
	log, buf := testLogger(t)
	dbPath := filepath.Join(t.TempDir(), "test.sqlite")
	s, err := Open(dbPath, log)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	ver, err := s.LatestVersion()
	if err != nil {
		t.Fatalf("LatestVersion: %v", err)
	}
	printIMPFromBuf(t, buf)
	if ver < 1 {
		t.Fatalf("expected schema version >= 1, got %d", ver)
	}

	// audit_log table must exist (used by audit chain tests).
	var n int
	if err := s.DB.QueryRow(`SELECT count(*) FROM audit_log`).Scan(&n); err != nil {
		t.Fatalf("audit_log table missing: %v", err)
	}
}

func TestOpen_IdempotentMigrations(t *testing.T) {
	log, _ := testLogger(t)
	dbPath := filepath.Join(t.TempDir(), "test.sqlite")
	s, err := Open(dbPath, log)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	// Reopen: must not re-apply or error.
	s2, err := Open(dbPath, log)
	if err != nil {
		t.Fatalf("reopen failed: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	ver, _ := s2.LatestVersion()
	if ver < 1 {
		t.Fatalf("expected version >= 1 after reopen, got %d", ver)
	}
}
