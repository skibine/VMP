// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8]: Crypto; TECH(8]: go test]
// @purpose Verify argon2id hash/verify, token uniqueness, and the deny-by-default middleware.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, hash, verify, argon2id, token, middleware, 401, public
// STRUCTURE: ▶ ┌store+session┐ → ○ Middleware → 〈token? public?〉 → ⎋ assert
package auth

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/skibine/vmp/internal/logging"
	"github.com/skibine/vmp/internal/store"
)

func openAuthStore(t *testing.T) *store.Store {
	t.Helper()
	var buf bytes.Buffer
	logger := logging.Setup(slog.LevelDebug, &buf)
	s, err := store.Open(filepath.Join(t.TempDir(), "auth.sqlite"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestHashVerify(t *testing.T) {
	h1, err := HashPassword("correct horse")
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := HashPassword("correct horse")
	if h1 == h2 {
		t.Fatal("two hashes of the same password should differ (random salt)")
	}
	if !VerifyPassword("correct horse", h1) {
		t.Fatal("verify should accept the correct password")
	}
	if VerifyPassword("wrong", h1) {
		t.Fatal("verify should reject the wrong password")
	}
	if VerifyPassword("x", "not-a-valid-encoded") {
		t.Fatal("verify should reject malformed encoded string")
	}
}

func TestNewToken_Unique(t *testing.T) {
	a, _ := NewToken()
	b, _ := NewToken()
	if a == "" || b == "" || a == b {
		t.Fatalf("tokens should be non-empty and unique: %q %q", a, b)
	}
}

func TestMiddleware_DenyByDefault(t *testing.T) {
	s := openAuthStore(t)
	logger := slog.Default()
	ctx := context.Background()

	uid, _ := s.CreateUser(ctx, "owner", "fakehash", "owner")
	tok, _ := NewToken()
	_ = s.CreateSession(ctx, tok, uid, time.Hour)

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if got, ok := FromContext(r.Context()); r.URL.Path != "/healthz" && r.URL.Path != "/api/auth/login" {
			if !ok || got != uid {
				t.Errorf("FromContext = (%d,%v), want (%d,true)", got, ok, uid)
			}
		}
		w.WriteHeader(http.StatusOK)
	})
	h := Middleware(s, logger)(next)

	// /healthz public -> next called.
	called = false
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if !called {
		t.Fatal("/healthz should be public")
	}

	// POST /api/auth/login public -> next called.
	called = false
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/auth/login", nil))
	if !called {
		t.Fatal("/api/auth/login should be public")
	}

	// /api/vms without token -> 401, next NOT called.
	called = false
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/vms", nil))
	if called || rec.Code != http.StatusUnauthorized {
		t.Fatalf("protected without token want 401 + not-called, got %d called=%v", rec.Code, called)
	}

	// /api/vms with valid Bearer -> 200, next called.
	called = false
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/vms", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	h.ServeHTTP(rec, req)
	if !called || rec.Code != http.StatusOK {
		t.Fatalf("protected with valid token want 200, got %d called=%v", rec.Code, called)
	}
}
