// Package auth — TOTP (RFC 6238) for two-factor authentication. Pure stdlib (HMAC-SHA1), no deps.
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): TOTP,2FA; TECH(8): crypto/hmac,base32]
// @purpose Provide time-based one-time passwords for second-factor login, compatible with any
//
//	TOTP authenticator (Google Authenticator, Authy, 1Password, …). 6 digits, 30s step, SHA-1.
//
// @io GenerateSecret() -> base32 ; Validate(secret, code, now, window) -> bool
// @invariants
//   - Secrets are 20 random bytes, base32-encoded without padding (the de-facto TOTP format).
//   - Validation allows ±window steps of skew and uses constant-time comparison.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: totp, 2fa, two-factor, authenticator, hmac, otp, rfc6231, secret
// STRUCTURE: ▶ ┌secret┐ → ◇ counter=now/30 → ⚡ HMAC-SHA1 dynamic-truncate → ⊕ 6-digit → 〈const-eq code〉 → bool
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash"
	"net/url"
	"strings"
	"time"
)

const (
	totpStep   = 30 * time.Second
	totpDigits = 6
	totpSkew   = 1 // allow ±1 step (±30s) for clock drift
)

// GenerateSecret returns a fresh base32 TOTP secret (20 random bytes, no padding).
func GenerateSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.EncodeToString(buf), nil
}

// hotp computes the 6-digit HOTP value for a counter using the shared secret (RFC 4226).
func hotp(secret string, counter uint64) (string, error) {
	key, err := base32Decode(secret)
	if err != nil {
		return "", err
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)
	mac := hmac.New(func() hash.Hash { return sha1.New() }, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := int(sum[len(sum)-1] & 0x0f)
	bin := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%0*d", totpDigits, bin%uint32(pow10(totpDigits))), nil
}

// ValidateStep checks a TOTP code and returns the matched counter step (for replay guards:
// callers persist it and refuse any future match with a step <= the stored one).
func ValidateStep(secret, code string, now time.Time) (int64, bool) {
	if len(code) != totpDigits {
		return 0, false
	}
	counter := int64(now.Unix()) / int64(totpStep.Seconds())
	for i := -totpSkew; i <= totpSkew; i++ {
		step := counter + int64(i)
		if c, err := hotp(secret, uint64(step)); err == nil {
			if subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
				return step, true
			}
		}
	}
	return 0, false
}

// Validate checks a TOTP code against the secret at `now`, allowing ±totpSkew steps of skew.
func Validate(secret, code string, now time.Time) bool {
	if len(code) != totpDigits {
		return false
	}
	counter := int64(now.Unix()) / int64(totpStep.Seconds())
	for i := -totpSkew; i <= totpSkew; i++ {
		// int64 counter avoids uint64 wrap on the negative-skew step (counter-1).
		if c, err := hotp(secret, uint64(counter+int64(i))); err == nil {
			if subtle.ConstantTimeCompare([]byte(c), []byte(code)) == 1 {
				return true
			}
		}
	}
	return false
}

// OTPAuthURI builds the otpauth:// URI consumed by authenticator apps (and encoded into a QR).
func OTPAuthURI(account, secret, issuer string) string {
	label := url.PathEscape(issuer + ":" + account)
	v := url.Values{}
	v.Set("secret", secret)
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", fmt.Sprintf("%d", totpDigits))
	v.Set("period", fmt.Sprintf("%d", int(totpStep.Seconds())))
	return "otpauth://totp/" + label + "?" + v.Encode()
}

// TOTPCode returns the current 6-digit code for a secret at `now` (handy for tests/CLI enrollment).
func TOTPCode(secret string, now time.Time) (string, error) {
	counter := uint64(now.Unix()) / uint64(totpStep.Seconds())
	return hotp(secret, counter)
}

// base32Decode decodes an uppercase/no-padding base32 secret tolerantly (lowercase, spaces).
func base32Decode(s string) ([]byte, error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return enc.DecodeString(strings.ToUpper(strings.ReplaceAll(s, " ", "")))
}

func pow10(n int) int {
	r := 1
	for i := 0; i < n; i++ {
		r *= 10
	}
	return r
}
