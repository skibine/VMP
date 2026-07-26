// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: SecretGen; TECH(8]: go test]
// @purpose Verify RandomPassword: length, charset membership, rough uniqueness, invalid length.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, random, password, secret, generator
package crypto

import (
	"strings"
	"testing"
)

func TestRandomPassword(t *testing.T) {
	p, err := RandomPassword(24)
	if err != nil {
		t.Fatalf("RandomPassword: %v", err)
	}
	if len(p) != 24 {
		t.Fatalf("want len 24, got %d (%q)", len(p), p)
	}
	for _, r := range p {
		if !strings.ContainsRune(passwordAlphabet, r) {
			t.Fatalf("char %q not in alphabet (password %q)", r, p)
		}
	}
	// Two draws should differ (collisions on 24 chars are astronomically unlikely).
	p2, _ := RandomPassword(24)
	if p == p2 {
		t.Fatalf("two draws identical — entropy problem: %q", p)
	}
	if _, err := RandomPassword(0); err == nil {
		t.Fatalf("want error for length 0")
	}
}
