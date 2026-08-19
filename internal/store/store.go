// Package store opens and migrates the SQLite database that is the single source of
// truth for VM Pulse (config / metrics / incidents / audit).
//
// region MODULE_CONTRACT [DOMAIN(8): Storage; CONCEPT(7): Persistence; TECH(9): SQLite,WAL,embed]
// @purpose Provide a ready-to-use *sql.DB in WAL mode with all embedded migrations applied,
//
//	so every other package can assume the schema exists and is versioned.
//
// @io (dbPath string, logger *slog.Logger) -> (*Store, error)
// @uses modernc.org/sqlite (pure Go, no CGO), embed, database/sql, path/filepath
// @invariants
//   - Open ALWAYS returns a WAL-mode, foreign-keys-on database or an error.
//   - Migrations are idempotent (schema_versions guards re-application).
//   - The SQLite driver is pure-Go (CGO-free) to keep GoReleaser cross-compilation intact.
//
// @rationale
//
//	Q: Why modernc.org/sqlite over mattn/go-sqlite3?
//	A: mattn needs CGO; CGO breaks clean cross-compilation (Win/Linux/macOS × x64/arm64)
//	   which is a hard product requirement (foundation-v2 §11). modernc is pure Go.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: SQLite, modernc, WAL, migrations, schema_versions, store, embed, persistence
// STRUCTURE: ▶ ┌dbPath┐ → ○ sql.Open(modernc) → ⚡ PRAGMA WAL/FK → ⊕ embed migrations → ∑ apply → ⎷ *Store
package store

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"io/fs"
	"log/slog"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/skibine/vm-pulse/internal/crypto"
	"github.com/skibine/vm-pulse/internal/logging"
	_ "modernc.org/sqlite" // pure-Go SQLite driver registration
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// region STRUCT_Store [DOMAIN(8): Storage; CONCEPT(7): Handle; TECH(8): database/sql]
// @purpose Wrap *sql.DB with a migration-aware lifecycle for VM Pulse. The optional vault, when
//
//	armed, transparently encrypts/decrypts secret-bearing columns at the boundary.
//
// endregion STRUCT_Store
type Store struct {
	DB     *sql.DB
	logger *slog.Logger
	vault  *crypto.Vault // nil = at-rest encryption disabled
}

// VaultArmed reports whether at-rest encryption is active (false = secrets stored plaintext;
// the UI renders a persistent warning banner in server mode).
func (s *Store) VaultArmed() bool { return s.vault != nil }

// region FUNC_Open [DOMAIN(8): Storage; CONCEPT(8): Bootstrap; TECH(9): SQLite,WAL]
// @purpose Open (or create) the database file, enable WAL + foreign keys, and bring the
//
//	schema to the latest embedded migration. The first Plane A service event can be
//	written immediately after this returns successfully.
//
// @io (dbPath string, logger *slog.Logger) -> (*Store, error)
// @complexity 6
// @invariants
//   - On error no partially-migrated *Store is returned.
//   - The parent directory of dbPath is created if missing.
//
// endregion FUNC_Open
func Open(dbPath string, logger *slog.Logger) (*Store, error) {
	if err := ensureParentDir(dbPath); err != nil {
		return nil, fmt.Errorf("store: ensure dir: %w", err)
	}
	// modernc.org/sqlite driver name is "sqlite".
	dsn := "file:" + dbPath + "?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(on)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		logging.LDD(logger, 10, "Open", "OPEN_FAIL", err.Error())
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// Single writer is fine for SQLite; cap pool to avoid "database is locked" surprises.
	db.SetMaxOpenConns(1)

	if err := db.PingContext(context.Background()); err != nil {
		_ = db.Close()
		logging.LDD(logger, 10, "Open", "PING_FAIL", err.Error())
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	s := &Store{DB: db, logger: logger}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		logging.LDD(logger, 10, "Open", "MIGRATE_FAIL", err.Error())
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	logging.LDD(logger, 8, "Open", "READY", fmt.Sprintf("db ready at %s", dbPath))
	return s, nil
}

// region FUNC_migrate [DOMAIN(8): Storage; CONCEPT(8): Migrations; TECH(8): embed,sql]
// @purpose Discover embedded .sql migration files, apply any not yet recorded in
//
//	schema_versions, and record each applied version. Idempotent and ordered.
//
// @io () -> error
// @complexity 7
// @invariants
//   - Migrations run in lexical filename order.
//   - A migration already present in schema_versions is never re-run.
//
// endregion FUNC_migrate
func (s *Store) migrate() error {
	// Bootstrap: guarantee the migration ledger exists BEFORE we query it. Migration 0001
	// also creates it (IF NOT EXISTS), but we need it present for isApplied() on a fresh DB.
	const bootstrap = `
CREATE TABLE IF NOT EXISTS schema_versions (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
    label      TEXT    NOT NULL
);`
	if _, err := s.DB.Exec(bootstrap); err != nil {
		return fmt.Errorf("bootstrap schema_versions: %w", err)
	}

	names, err := fs.ReadDir(migrationFS, "migrations")
	if err != nil {
		return fmt.Errorf("read migrations dir: %w", err)
	}
	files := make([]string, 0, len(names))
	for _, n := range names {
		if strings.HasSuffix(n.Name(), ".sql") {
			files = append(files, n.Name())
		}
	}
	sort.Strings(files)

	for _, name := range files {
		applied, err := s.isApplied(name)
		if err != nil {
			return err
		}
		if applied {
			continue
		}
		body, rerr := migrationFS.ReadFile(path.Join("migrations", name))
		if rerr != nil {
			return fmt.Errorf("read %s: %w", name, rerr)
		}
		// Apply each migration file inside a transaction so a mid-file failure cannot leave the
		// schema half-applied (which would brick startup on re-run with "duplicate column"). The
		// schema_versions ledger is updated inside the same tx below, so isApplied stays correct.
		if err := s.execMigrationTx(context.Background(), string(body), name); err != nil {
			return fmt.Errorf("exec %s: %w", name, err)
		}
		logging.LDD(s.logger, 8, "migrate", "APPLIED", name)
	}
	ver, _ := s.LatestVersion()
	logging.LDD(s.logger, 8, "migrate", "DONE", fmt.Sprintf("latest schema version=%d", ver))
	return nil
}

// execMigrationTx applies one migration file's statements atomically. SQLite supports multiple
// statements in a single Exec; wrapping in BEGIN/COMMIT guarantees all-or-nothing per file.
func (s *Store) execMigrationTx(ctx context.Context, body, name string) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, body); err != nil {
		return err
	}
	return tx.Commit()
}

// isApplied reports whether a migration file's version is recorded. The version is derived
// from the leading numeric segment of the filename (e.g. "0001_init.sql" -> 1).
func (s *Store) isApplied(name string) (bool, error) {
	ver := versionFromName(name)
	var got int
	err := s.DB.QueryRow(`SELECT version FROM schema_versions WHERE version = ?`, ver).Scan(&got)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("check %s: %w", name, err)
	}
	return true, nil
}

// versionFromName parses "0001_init.sql" -> 1. Falls back to 0 on parse failure.
func versionFromName(name string) int {
	prefix := name
	if i := strings.IndexByte(name, '_'); i > 0 {
		prefix = name[:i]
	}
	var v int
	_, _ = fmt.Sscanf(prefix, "%d", &v)
	return v
}

// LatestVersion returns the highest applied schema version (0 if none / table missing).
func (s *Store) LatestVersion() (int, error) {
	var v int
	err := s.DB.QueryRow(`SELECT COALESCE(MAX(version),0) FROM schema_versions`).Scan(&v)
	return v, err
}

// region FUNC_Close [DOMAIN(8): Storage; CONCEPT(5): Lifecycle; TECH(4): sql]
// @purpose Release the database handle cleanly.
// @complexity 2
// endregion FUNC_Close
func (s *Store) Close() error {
	if s == nil || s.DB == nil {
		return nil
	}
	return s.DB.Close()
}

// ensureParentDir creates the directory containing dbPath if it does not exist.
func ensureParentDir(dbPath string) error {
	dir := filepath.Dir(dbPath)
	if dir == "" || dir == "." {
		return nil
	}
	return mkdirAllSafe(dir)
}
