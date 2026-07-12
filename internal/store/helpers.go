// Package store — internal filesystem helpers.
//
// region MODULE_CONTRACT [DOMAIN(6): Storage; CONCEPT(5): FS; TECH(6): os]
// @purpose Small, testable filesystem helpers for the store package.
// @invariants
//   - mkdirAllSafe never errors when the directory already exists.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: mkdir, directory, fs, helper
// STRUCTURE: ▶ ┌dir┐ → ○ MkdirAll(0700) → ⎷ nil
package store

import "os"

// region FUNC_mkdirAllSafe [DOMAIN(6): Storage; CONCEPT(5): FS; TECH(6): os]
// @purpose Create a directory (and parents) with restrictive 0700 perms, tolerating the
//
//	"already exists" case. DB files hold potentially sensitive data, so the dir is
//	owner-only by default.
//
// @io dir string -> error
// @complexity 2
// endregion FUNC_mkdirAllSafe
func mkdirAllSafe(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	return nil
}
