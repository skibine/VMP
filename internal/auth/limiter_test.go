// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): LoginHardening; TECH(8): go test]
// @purpose Verify the brute-force damper: limiter window math, login 429 after N attempts,
//
//	success clears the counter, and the anti-enumeration dummy hash path never leaks timing.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, rate limit, limiter, login, 429, brute force, dummy hash
package auth

import (
	"testing"
	"time"
)

// region FUNC_test_Limiter [DOMAIN(7): Testing; CONCEPT(7): SlidingWindow; TECH(5): table]
// @purpose Window math: max allowed then deny; expiry re-admits; Clear forgets.
// @complexity 3
// endregion FUNC_test_Limiter
func TestLimiter_SlidingWindow(t *testing.T) {
	l := NewLimiter(3, 40*time.Millisecond)
	for i := 0; i < 3; i++ {
		if !l.Allow("k") {
			t.Fatalf("attempt %d must fit the window", i+1)
		}
	}
	if l.Allow("k") {
		t.Fatal("4th attempt must be denied")
	}
	// A different key is independent.
	if !l.Allow("other") {
		t.Fatal("other key must be unaffected")
	}
	// Clear forgets: the very next attempt fits.
	l.Clear("k")
	if !l.Allow("k") {
		t.Fatal("after Clear the next attempt must fit")
	}
	// Window slides: after expiry, attempts fit again.
	l2 := NewLimiter(1, 20*time.Millisecond)
	if !l2.Allow("w") || l2.Allow("w") {
		t.Fatal("second immediate attempt must be denied")
	}
	time.Sleep(25 * time.Millisecond)
	if !l2.Allow("w") {
		t.Fatal("after the window slides the attempt must fit")
	}
	t.Logf("[IMP:8][TestLimiter][RESULT] window+clear+slide ok")
}

// endregion FUNC_test_Limiter
