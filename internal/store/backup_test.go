// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: Backup; TECH(8]: go test,SQLite]
// @purpose Verify Store.Backup (VACUUM INTO): a snapshot is a consistent, re-openable copy that
//
//	contains committed data; an existing destination is refused; printing [IMP:7-9] anchors.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, backup, vacuum into, snapshot, sqlite, recovery
// STRUCTURE: ▶ ┌store+row┐ → ○ Backup → ⚡ store.Open(dest) → 〈row present?〉 → ⎋ assert
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

// TestBackup_RoundTrip writes a VM, snapshots it, re-opens the snapshot and confirms the VM
// survived the copy (so a restore from .bak is trustworthy).
func TestBackup_RoundTrip(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := t.Context()

	id, err := s.CreateVM(ctx, VM{Name: "web1", Hostname: "10.0.0.1", PortSSH: 22})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}

	dest := filepath.Join(t.TempDir(), "snap.sqlite")
	if err := s.Backup(ctx, dest); err != nil {
		t.Fatalf("Backup: %v", err)
	}

	// Re-open the snapshot (migrations are idempotent over the copied schema_versions).
	var buf bytes.Buffer
	s2, err := Open(dest, logging.Setup(slog.LevelDebug, &buf))
	if err != nil {
		t.Fatalf("open snapshot: %v", err)
	}
	defer s2.Close()

	vms, err := s2.ListVMs(ctx, false)
	if err != nil {
		t.Fatalf("ListVMs on snapshot: %v", err)
	}
	if len(vms) != 1 || vms[0].ID != id || vms[0].Name != "web1" {
		t.Fatalf("snapshot missing the VM: %+v", vms)
	}
	printIMPLines(t, &buf)
}

// TestBackup_RefusesExisting documents the VACUUM INTO invariant: the caller must remove dest
// first (backupLoop does this before every tick).
func TestBackup_RefusesExisting(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := t.Context()
	dest := filepath.Join(t.TempDir(), "snap.sqlite")

	if err := s.Backup(ctx, dest); err != nil {
		t.Fatalf("first Backup: %v", err)
	}
	// Second call without removing dest must fail (no silent overwrite of a good backup).
	if err := s.Backup(ctx, dest); err == nil {
		t.Fatalf("expected error overwriting existing destination")
	}
}

// TestBackup_RejectsBadPath verifies the quote-injection guard on the interpolated filename.
func TestBackup_RejectsBadPath(t *testing.T) {
	s, _ := openTestStore(t)
	if err := s.Backup(t.Context(), filepath.Join(t.TempDir(), "x' OR '1'='1")); err == nil {
		t.Fatalf("expected error for quote-containing path")
	}
}

// printIMPLines logs the IMP:7-9 trajectory from the buffer (Semantic Trace Verification).
func printIMPLines(t *testing.T, buf *bytes.Buffer) {
	t.Helper()
	t.Log("--- LDD TRAJECTORY (IMP:7-9) ---")
	for _, line := range strings.Split(buf.String(), "\n") {
		if i, ok := lddcheck.IMPValue(line); ok && i >= 7 && i <= 9 {
			t.Log(line)
		}
	}
}
