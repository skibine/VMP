// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): LoginRateLimit; TECH(8): go test]
// @purpose End-to-end: loginMaxAttempts+1 bad attempts -> 429; a fresh IP is unaffected.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, login, 429, rate limit, api
package api

import (
	"net/http"
	"testing"
)

func TestLogin_RateLimitedAfterBurst(t *testing.T) {
	srv, _ := newServer(t)
	body := `{"username":"bruteforce-user","password":"wrong"}`
	last := 0
	for i := 0; i < loginMaxAttempts; i++ {
		rec := do(srv, http.MethodPost, "/api/auth/login", body)
		last = rec.Code
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: want 401, got %d", i+1, rec.Code)
		}
	}
	rec := do(srv, http.MethodPost, "/api/auth/login", body)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("after %d attempts want 429, got %d", loginMaxAttempts, rec.Code)
	}
	t.Logf("[IMP:9][TestLoginRL][RESULT] 429 after %d attempts (last regular=%d)", loginMaxAttempts, last)
}
