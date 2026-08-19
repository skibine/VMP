// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8]: AuthAPI; TECH(8]: go test,httptest]
// @purpose Verify login (ok/401), middleware (401 without token, 200 with), /healthz public,
//
//	/api/auth/me, and logout.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, login, middleware, 401, 200, me, logout, public
// STRUCTURE: ▶ ┌server+Use(mw)┐ → POST login → ○ token → 〈protected?〉 → ⎋ assert
package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skibine/vmp/internal/auth"
)

// doH drives a specific handler (the middleware-wrapped one) with an optional bearer token.
func doH(h http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, path, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHTTP_Auth_LoginAndMiddleware(t *testing.T) {
	srv, buf := newServer(t)
	hash, _ := auth.HashPassword("s3cret")
	_, _ = srv.store.CreateUser(context.Background(), "owner", hash, "owner")
	srv.Use(auth.Middleware(srv.store, srv.logger))
	h := srv.srv.Handler

	// Login wrong -> 401.
	rec := doH(h, http.MethodPost, "/api/auth/login", `{"username":"owner","password":"wrong"}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("wrong creds want 401, got %d", rec.Code)
	}

	// Login correct -> 200 + token.
	rec = doH(h, http.MethodPost, "/api/auth/login", `{"username":"owner","password":"s3cret"}`, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("login want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var lb map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&lb)
	token, _ := lb["token"].(string)
	if token == "" {
		t.Fatal("login did not return a token")
	}

	// /healthz public (no token).
	if rec := doH(h, http.MethodGet, "/healthz", "", ""); rec.Code != http.StatusOK {
		t.Fatalf("/healthz want 200, got %d", rec.Code)
	}

	// Protected without token -> 401.
	if rec := doH(h, http.MethodGet, "/api/vms", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("protected no-token want 401, got %d", rec.Code)
	}

	// Protected with token -> 200.
	if rec := doH(h, http.MethodGet, "/api/vms", "", token); rec.Code != http.StatusOK {
		t.Fatalf("protected with token want 200, got %d", rec.Code)
	}

	// /api/auth/me with token -> username.
	rec = doH(h, http.MethodGet, "/api/auth/me", "", token)
	if rec.Code != http.StatusOK {
		t.Fatalf("me want 200, got %d", rec.Code)
	}
	var me map[string]any
	_ = json.NewDecoder(rec.Body).Decode(&me)
	if me["username"] != "owner" {
		t.Fatalf("me username want owner, got %v", me["username"])
	}

	// Logout invalidates the token.
	if rec := doH(h, http.MethodPost, "/api/auth/logout", "", token); rec.Code != http.StatusOK {
		t.Fatalf("logout want 200, got %d", rec.Code)
	}
	if rec := doH(h, http.MethodGet, "/api/vms", "", token); rec.Code != http.StatusUnauthorized {
		t.Fatalf("after logout token should be invalid (401), got %d", rec.Code)
	}

	printIMPFromBuf(t, buf)
	assertContains(t, buf, "[IMP:9][login][OK]")
}
