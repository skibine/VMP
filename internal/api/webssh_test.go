// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(9]: WebSSHLimit; TECH(6]: go test]
// @purpose Verify the per-user web-SSH session registry enforces its limit and releases slots.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, web-ssh, session, limit, registry, concurrency
package api

import (
	"testing"
	"time"
)

func TestSessionRegistry_LimitAndRelease(t *testing.T) {
	r := newSessionRegistry()
	const uid int64 = 42
	const limit = 2

	// First two slots acquired.
	if !r.acquire(uid, limit) {
		t.Fatal("first acquire should succeed")
	}
	if !r.acquire(uid, limit) {
		t.Fatal("second acquire should succeed")
	}
	// Third exceeds the per-user limit.
	if r.acquire(uid, limit) {
		t.Fatal("third acquire must be refused (limit reached)")
	}
	// Release one, then a slot opens up again.
	r.release(uid)
	if !r.acquire(uid, limit) {
		t.Fatal("acquire after release should succeed")
	}
	// Double-release must not underflow the count.
	r.release(uid)
	r.release(uid)
	r.release(uid)
	// After draining, the user is fully released and can acquire up to the limit again.
	if !r.acquire(uid, limit) {
		t.Fatal("acquire after draining should succeed")
	}
}

func TestSessionRegistry_PerUserIsolation(t *testing.T) {
	r := newSessionRegistry()
	// User A hits the limit; user B is unaffected (separate counter).
	const a, b int64 = 1, 2
	r.acquire(a, 1)
	if r.acquire(a, 1) {
		t.Fatal("user A should be at limit")
	}
	if !r.acquire(b, 1) {
		t.Fatal("user B should be independent of user A's limit")
	}
}

func TestSetWebSSHDefaults(t *testing.T) {
	// Restore package defaults after the test so it doesn't leak into other tests.
	t.Cleanup(func() {
		webSSHSessionLimit = 3
		webSSHIdleTimeout = 30 * time.Minute
	})
	SetWebSSHDefaults(5, 7)
	if webSSHSessionLimit != 5 {
		t.Fatalf("limit want 5, got %d", webSSHSessionLimit)
	}
	if webSSHIdleTimeout != 7*time.Minute {
		t.Fatalf("idle want 7m, got %v", webSSHIdleTimeout)
	}
	// Zero values are ignored (keep the configured values).
	SetWebSSHDefaults(0, 0)
	if webSSHSessionLimit != 5 {
		t.Fatalf("zero must not reset the configured limit, got %d", webSSHSessionLimit)
	}
}
