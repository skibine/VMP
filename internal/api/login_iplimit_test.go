// region FUNC_test_LoginIPRateLimit [DOMAIN(7): Testing; CONCEPT(8): Argon2DoSDamper; TECH(6): go test]
// @purpose Rotating usernames from one IP hits the per-IP cap (the dummy-argon2 DoS path).
// endregion
package api

import (
	"net/http"
	"testing"
)

func TestLogin_PerIPRateLimitOnUsernameRotation(t *testing.T) {
	srv, _ := newServer(t)
	// loginIPMaxAttempts-1 unique usernames fit; the NEXT one is 429 even though each
	// username is brand new (this is the cap the per-username limiter cannot provide).
	for i := 0; i < loginIPMaxAttempts; i++ {
		rec := do(srv, http.MethodPost, "/api/auth/login",
			`{"username":"rot`+string(rune('a'+i%26))+string(rune('a'+i/26))+`","password":"x"}`)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("attempt %d hit the IP cap too early", i+1)
		}
	}
	rec := do(srv, http.MethodPost, "/api/auth/login", `{"username":"fresh-user-9","password":"x"}`)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rotated usernames must hit the per-IP cap, got %d", rec.Code)
	}
	t.Logf("[IMP:9][TestIPRateLimit][RESULT] per-IP cap enforced across username rotation")
}
