// Package store — online backup via SQLite VACUUM INTO.
//
// region MODULE_CONTRACT [DOMAIN(8): Storage; CONCEPT(8): Backup; TECH(8): SQLite,VACUUM INTO]
// @purpose Take a consistent point-in-time snapshot of the database file to <dbpath>.bak so the
//
//	single source of truth (config + metrics + the tamper-evident audit chain) is recoverable
//	if the primary file is corrupted or lost. Called on startup and daily by cmd/vmpulse.
//
// @io Backup(ctx, dest string) -> error
// @invariants
//   - VACUUM INTO refuses to overwrite an existing file -> the caller removes dest first.
//   - The destination path is sanitized against quote injection (it is interpolated into SQL).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: backup, vacuum into, snapshot, recovery, sqlite, bak, disaster
// STRUCTURE: ▶ ┌dest┐ → 〈sanitize?〉 → ⚡ VACUUM INTO 'dest' → ⎋ error?
package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/skibine/vmp/internal/logging"
)

// region FUNC_Backup [DOMAIN(8): Storage; CONCEPT(7): Snapshot; TECH(8): SQLite,VACUUM INTO]
// @purpose Write a transactionally-consistent copy of the database to dest via VACUUM INTO.
// @complexity 3
// @invariants
//   - Returns an error (and writes no file) if dest already exists — caller must remove it first.
//
// endregion FUNC_Backup
func (s *Store) Backup(ctx context.Context, dest string) error {
	// VACUUM INTO takes a literal filename (not a bound parameter), so guard against breaking out
	// of the quoted string. dest is operator/dbpath-controlled, but defense-in-depth is cheap.
	if strings.ContainsAny(dest, "'\x00") {
		return fmt.Errorf("Backup: invalid destination path")
	}
	if _, err := s.DB.ExecContext(ctx, fmt.Sprintf("VACUUM INTO '%s'", dest)); err != nil {
		logging.LDD(s.logger, 9, "Backup", "FAIL", err.Error())
		return fmt.Errorf("Backup: %w", err)
	}
	logging.LDD(s.logger, 7, "Backup", "DONE", dest)
	return nil
}
