// Package store — sessions repository (server-side, bearer-token sessions).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(7): Sessions; TECH(8): database/sql]
// @purpose Persist session tokens with an absolute expiry. The auth middleware treats expired
//
//	rows as invalid; this repo does not auto-clean (a retention job can be added later).
//
// @invariants
//   - token is the PRIMARY KEY (random, opaque, base64url).
//   - GetSession returns ok=false for missing OR expired rows.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: sessions, CreateSession, GetSession, DeleteSession, token, TTL, expiry
// STRUCTURE: ▶ ┌token┐ → ○ INSERT(expires_at) → ⎋ ; Get → 〈now<expires?〉 → ⎷ userID
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// CreateSession inserts a session token for userID expiring ttl from now; returns the token.
func (s *Store) CreateSession(ctx context.Context, token string, userID int64, ttl time.Duration) error {
	expires := time.Now().Add(ttl).UTC().Format(time.RFC3339Nano)
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)`, token, userID, expires)
	if err != nil {
		return fmt.Errorf("CreateSession: %w", err)
	}
	return nil
}

// GetSession returns the userID for a valid (existing, non-expired) token.
func (s *Store) GetSession(ctx context.Context, token string) (int64, bool, error) {
	var userID int64
	var expires string
	err := s.DB.QueryRowContext(ctx,
		`SELECT user_id, expires_at FROM sessions WHERE token = ?`, token).Scan(&userID, &expires)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("GetSession: %w", err)
	}
	exp, perr := time.Parse(time.RFC3339Nano, expires)
	if perr != nil {
		return 0, false, nil
	}
	if time.Now().After(exp) {
		return 0, false, nil
	}
	return userID, true, nil
}

// DeleteSession removes a session token (logout).
func (s *Store) DeleteSession(ctx context.Context, token string) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE token = ?`, token)
	return err
}
