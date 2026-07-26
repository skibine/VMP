// Package crypto — random secret generation.
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(7): SecretGen; TECH(8): crypto/rand]
// @purpose Generate one-time secrets (bootstrap admin password, tokens) from crypto/rand using a
//
//	human-friendly alphabet (no ambiguous 0/O/1/l) so they can be read/typed from a console.
//
// @io RandomPassword(n int) -> (string, error)
// @invariants
//   - Output only contains characters from passwordAlphabet.
//   - Length of the result equals n (for n >= 1).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: random, password, token, crypto/rand, secret, bootstrap, generator
// STRUCTURE: ▶ ┌n┐ → ○ rand.Read(n) → ⊕ map→alphabet → ⎋ string
package crypto

import (
	"crypto/rand"
	"errors"
)

// passwordAlphabet excludes visually-ambiguous glyphs (0/O, 1/l/I) so a printed bootstrap password
// is legible from a console or journal.
const passwordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789"

// region FUNC_RandomPassword [DOMAIN(9): Security; CONCEPT(7): SecretGen; TECH(8): crypto/rand]
// @purpose Produce a one-time human-legible secret of length n for first-run bootstrap or tokens.
// @io (n int) -> (string, error)
// @complexity 2
// @rationale
//
//	Q: Why modulo mapping over the alphabet instead of rejection sampling?
//	A: The result is a one-time bootstrap credential the operator changes immediately, not a key;
//	   the tiny modulo bias (alphabet length 56) is cryptographically irrelevant here, and modulo
//	   keeps the code dependency-free and constant-time-ish in length.
//
// endregion FUNC_RandomPassword
func RandomPassword(n int) (string, error) {
	if n < 1 {
		return "", errors.New("RandomPassword: length must be >= 1")
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	for i := range buf {
		buf[i] = passwordAlphabet[int(buf[i])%len(passwordAlphabet)]
	}
	return string(buf), nil
}
