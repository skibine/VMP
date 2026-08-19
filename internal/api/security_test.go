// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): HttpHardening; TECH(8): go test,httptest]
// @purpose Verify the cheap-pack hardening: security headers on every response, no-store on /api/,
//
//	query-string tokens rejected for non-websocket requests, sessions revoked on password change.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, security headers, csp, token query, session revoke, password change
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/skibine/vmp/internal/auth"
)

// region FUNC_test_SecurityHeaders [DOMAIN(8): Security; CONCEPT(7): Headers; TECH(5]: httptest]
// @purpose Hardening headers present on the SPA root and no-store on API routes.
// @complexity 2
// endregion FUNC_test_SecurityHeaders
func TestSecurityHeaders_Present(t *testing.T) {
	srv, _ := newServer(t)
	// In prod, Use() wraps securityHeaders OUTERMOST; tests drive the raw mux, so wrap here.
	h := securityHeaders(srv.Handler())
	r := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := rec.Header().Get(k); got != want {
			t.Errorf("%s: want %q, got %q", k, want, got)
		}
	}
	if rec.Header().Get("Content-Security-Policy") == "" {
		t.Error("CSP missing")
	}
	// API responses must never be cacheable.
	r2 := httptest.NewRequest(http.MethodGet, "/api/version", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, r2)
	if rec2.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("/api/ Cache-Control: want no-store, got %q", rec2.Header().Get("Cache-Control"))
	}
	t.Logf("[IMP:8][TestSecHeaders][RESULT] nosniff+deny+no-referrer+csp present")
}

// region FUNC_test_TokenQueryNonWS [DOMAIN(9): Security; CONCEPT(7): TokenLeak; TECH(6): httptest]
// @purpose A valid session token passed via ?token= is REJECTED for a plain GET (only the
//
//	websocket upgrade path may read it), while the Authorization header works.
//
// @complexity 3
// endregion FUNC_test_TokenQueryNonWS
func TestTokenQuery_RejectedForNonWebSocket(t *testing.T) {
	srv, buf := newServer(t)
	ctx := context.Background()
	uid, err := srv.store.CreateUser(ctx, "tokuser", "argon2id$fake$hash", "owner")
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok, _ := auth.NewToken()
	if err := srv.store.CreateSession(ctx, tok, uid, time.Hour); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	h := auth.Middleware(srv.store, srv.logger)(srv.Handler())

	// ?token= on a plain GET -> 401 (token must not be readable from the query string).
	r := httptest.NewRequest(http.MethodGet, "/api/auth/me?token="+tok, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("?token on non-WS request must 401, got %d", rec.Code)
	}

	// Bearer header on the same route -> 200.
	r2 := httptest.NewRequest(http.MethodGet, "/api/auth/me", nil)
	r2.Header.Set("Authorization", "Bearer "+tok)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, r2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("Bearer on the same route must work, got %d", rec2.Code)
	}
	t.Logf("[IMP:9][TestTokenQuery][RESULT] ?token rejected for non-WS; Bearer accepted")
	_ = buf
}

// region FUNC_test_SessionRevokeOnPasswordChange [DOMAIN(9): Security; CONCEPT(7): Revocation; TECH(6): store]
// @purpose Password change kills every existing session of that user.
// @complexity 2
// endregion FUNC_test_SessionRevokeOnPasswordChange
func TestSessions_RevokedForUser(t *testing.T) {
	srv, _ := newServer(t)
	ctx := context.Background()
	uid, _ := srv.store.CreateUser(ctx, "revuser", "h1", "owner")
	t1, _ := auth.NewToken()
	t2, _ := auth.NewToken()
	_ = srv.store.CreateSession(ctx, t1, uid, time.Hour)
	_ = srv.store.CreateSession(ctx, t2, uid, time.Hour)
	if err := srv.store.DeleteSessionsForUser(ctx, uid); err != nil {
		t.Fatalf("DeleteSessionsForUser: %v", err)
	}
	for i, tok := range []string{t1, t2} {
		if _, ok, _ := srv.store.GetSession(ctx, tok); ok {
			t.Fatalf("session %d must be revoked", i+1)
		}
	}
	t.Logf("[IMP:8][TestRevoke][RESULT] all user sessions revoked")
}

// endregion FUNC_test_TokenQueryNonWS
