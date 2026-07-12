// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: UsersSessions; TECH(8]: go test]
// @purpose Verify users + sessions repos: create/duplicate, lookup, count, last-login,
//
//	session TTL expiry and delete.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, users, sessions, duplicate, TTL, delete, last_login
// STRUCTURE: ▶ ┌store┐ → ⊕ user/session → ○ get → ⚡ expire → 〈ok?〉 → ⎋ assert
package store

import (
	"context"
	"testing"
	"time"
)

func TestUsers_CRUD(t *testing.T) {
	s, buf := openTestStore(t)
	ctx := context.Background()

	id, err := s.CreateUser(ctx, "alice", "hash1", "owner")
	if err != nil || id == 0 {
		t.Fatalf("CreateUser: %v (id %d)", err, id)
	}
	if _, err := s.CreateUser(ctx, "alice", "hash2", "owner"); err != ErrDuplicate {
		t.Fatalf("duplicate username want ErrDuplicate, got %v", err)
	}
	u, err := s.GetUserByUsername(ctx, "alice")
	if err != nil || u.ID != id || u.Role != "owner" || !u.IsActive {
		t.Fatalf("GetUserByUsername mismatch: %+v err %v", u, err)
	}
	if n, _ := s.CountUsers(ctx); n != 1 {
		t.Fatalf("CountUsers want 1, got %d", n)
	}
	if err := s.SetLastLogin(ctx, id); err != nil {
		t.Fatalf("SetLastLogin: %v", err)
	}
	u2, _ := s.GetUser(ctx, id)
	if u2.LastLoginAt == "" {
		t.Fatal("LastLoginAt should be set")
	}
	_ = buf
}

func TestSessions_TTLAndDelete(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	uid, _ := s.CreateUser(ctx, "bob", "h", "owner")

	tok := "token-abc"
	if err := s.CreateSession(ctx, tok, uid, time.Hour); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	got, ok, err := s.GetSession(ctx, tok)
	if err != nil || !ok || got != uid {
		t.Fatalf("GetSession want (%d,true), got (%d,%v) err %v", uid, got, ok, err)
	}

	// Expire it manually.
	if _, err := s.DB.Exec(`UPDATE sessions SET expires_at=strftime('%Y-%m-%dT%H:%M:%fZ','now','-1 hour') WHERE token=?`, tok); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.GetSession(ctx, tok); ok {
		t.Fatal("expired session should be invalid")
	}

	// Unknown token -> not ok.
	if _, ok, _ := s.GetSession(ctx, "nope"); ok {
		t.Fatal("unknown token should be invalid")
	}

	// Fresh session then delete.
	tok2 := "token-xyz"
	_ = s.CreateSession(ctx, tok2, uid, time.Hour)
	if err := s.DeleteSession(ctx, tok2); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	if _, ok, _ := s.GetSession(ctx, tok2); ok {
		t.Fatal("deleted session should be invalid")
	}
}
