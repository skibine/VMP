// Package store — shared repository utilities.
//
// region MODULE_CONTRACT [DOMAIN(6): Storage; CONCEPT(6): SQLUtil; TECH(6): database/sql]
// @purpose Common scanning/result helpers and the not-found sentinel used by all repos.
// @invariants
//   - scanner is satisfied by both *sql.Row and *sql.Rows (both have Scan).
//   - rowsAffected returns ErrNotFound when zero rows matched an UPDATE/DELETE.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: scanner, rowsAffected, ErrNotFound, bool, helper
// STRUCTURE: ▶ ┌result┐ → ○ RowsAffected → 〈0? ErrNotFound : nil〉 → ⎷
package store

import (
	"database/sql"
	"errors"
)

// ErrNotFound is returned by Update/Delete/Get when no row matched the id.
var ErrNotFound = errors.New("store: not found")

// scanner is implemented by *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

// toBoolInt converts a bool to a stored INTEGER (0/1).
func toBoolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// rowsAffected wraps a sql.Result, returning ErrNotFound when zero rows changed.
func rowsAffected(res sql.Result, name string, id int64) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// isNoRows reports whether err is the driver's "no rows" sentinel.
func isNoRows(err error) bool { return errors.Is(err, sql.ErrNoRows) }
