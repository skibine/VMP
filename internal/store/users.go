// Package store — users repository (Plane B access control).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(7): Users; TECH(8): database/sql]
// @purpose Persist user accounts. Password hashing lives in internal/auth; this repo stores
//
//	the pre-hashed password_hash only (never plaintext).
//
// @invariants
//   - username is UNIQUE; CreateUser on a duplicate returns ErrDuplicate.
//   - role is 'owner' | 'guest' (full RBAC matrix is a future slice).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: users, CreateUser, GetUserByUsername, GetUser, CountUsers, SetLastLogin, owner, guest
// STRUCTURE: ▶ ┌User┐ → ○ INSERT (hashed pw) → ⎋ id ; read by username/id
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// region STRUCT_User [DOMAIN(9): Security; CONCEPT(7): Account; TECH(6): struct]
// @purpose A user account. PasswordHash holds an argon2id encoded string.
// endregion STRUCT_User
type User struct {
	ID           int64  `json:"id"`
	Username     string `json:"username"`
	PasswordHash string `json:"-"` // never serialized
	PasswordAlgo string `json:"password_algo"`
	Role         string `json:"role"` // owner | guest
	IsActive     bool   `json:"is_active"`
	CreatedAt    string `json:"created_at"`
	LastLoginAt  string `json:"last_login_at"`
}

// CreateUser inserts a user with a pre-hashed password. role defaults to "owner" if empty.
func (s *Store) CreateUser(ctx context.Context, username, passwordHash, role string) (int64, error) {
	if role == "" {
		role = "owner"
	}
	res, err := s.DB.ExecContext(ctx, `
INSERT INTO users (username, password_hash, password_algo, role) VALUES (?,?,?,?)`,
		username, passwordHash, "argon2id", role)
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrDuplicate
		}
		return 0, fmt.Errorf("CreateUser: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// GetUserByUsername returns the user for login lookups.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	return s.scanUser(ctx, `SELECT id, username, password_hash, password_algo, role, is_active, created_at, COALESCE(last_login_at,'')
FROM users WHERE username = ?`, username)
}

// GetUser returns a user by id.
func (s *Store) GetUser(ctx context.Context, id int64) (User, error) {
	return s.scanUser(ctx, `SELECT id, username, password_hash, password_algo, role, is_active, created_at, COALESCE(last_login_at,'')
FROM users WHERE id = ?`, id)
}

// CountUsers returns the total number of users (used by bootstrap).
func (s *Store) CountUsers(ctx context.Context) (int64, error) {
	var n int64
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

// SetLastLogin stamps the user's last_login_at to now.
func (s *Store) SetLastLogin(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE users SET last_login_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?`, id)
	return err
}

func (s *Store) scanUser(ctx context.Context, q string, args ...any) (User, error) {
	var u User
	var active int
	err := s.DB.QueryRowContext(ctx, q, args...).Scan(
		&u.ID, &u.Username, &u.PasswordHash, &u.PasswordAlgo, &u.Role, &active, &u.CreatedAt, &u.LastLoginAt)
	if err == sql.ErrNoRows {
		return User{}, ErrNotFound
	}
	if err != nil {
		return User{}, err
	}
	if u.LastLoginAt == "" {
		u.LastLoginAt = ""
	}
	u.IsActive = active != 0
	return u, nil
}
