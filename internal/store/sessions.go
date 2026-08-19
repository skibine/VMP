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

// region FUNC_DeleteSessionsForUser [DOMAIN(9): Security; CONCEPT(7): SessionRevocation; TECH(5): SQLite]
// @purpose Revoke EVERY session of a user (password change, 2FA toggle, lockout response) -
//
//	a stolen session must not outlive the credential that guards it.
//
// @complexity 2
// endregion FUNC_DeleteSessionsForUser
func (s *Store) DeleteSessionsForUser(ctx context.Context, userID int64) error {
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return fmt.Errorf("DeleteSessionsForUser: %w", err)
	}
	// Opportunistic hygiene: expired rows are invisible to GetSession anyway.
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`,
		time.Now().UTC().Format(time.RFC3339Nano))
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
