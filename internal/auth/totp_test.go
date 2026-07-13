package auth

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// region FUNC_test_TOTP_RFC6231 [DOMAIN(7): Testing; CONCEPT(7): TOTP; TECH(5): crypto]
// @purpose Verify TOTP against the RFC 6231 reference vectors (secret "1234567890..." 20 bytes).
// @complexity 3
// endregion FUNC_test_TOTP_RFC6231
func TestTOTP_RFC6231(t *testing.T) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	secret := enc.EncodeToString([]byte("12345678901234567890"))
	// RFC 8-digit values mod 10^6 give the 6-digit codes our impl produces.
	want6 := map[int64]string{59: "287082", 1111111109: "081804", 1111111111: "050471"}
	for sec, want := range want6 {
		if !Validate(secret, want, time.Unix(sec, 0)) {
			t.Errorf("RFC6231: expected code %s to validate at t=%d", want, sec)
		}
		if Validate(secret, "000000", time.Unix(sec, 0)) && want != "000000" {
			t.Errorf("RFC6231: 000000 must not validate at t=%d", sec)
		}
	}
	t.Logf("[IMP:8][TestTOTP][RFC6231] %d reference vectors validated", len(want6))
}

// region FUNC_test_TOTP_GenerateValidate [DOMAIN(6): Testing; CONCEPT(6): Roundtrip; TECH(3): crypto]
// @purpose A generated secret must validate a freshly-computed code and reject a wrong one.
// @complexity 2
// endregion FUNC_test_TOTP_GenerateValidate
func TestTOTP_GenerateValidate(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Now()
	counter := uint64(now.Unix()) / 30
	code, err := hotp(secret, counter)
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}
	if !Validate(secret, code, now) {
		t.Fatalf("freshly generated code %s did not validate", code)
	}
	uri := OTPAuthURI("admin", secret, "VMPulse")
	if !strings.HasPrefix(uri, "otpauth://totp/") || !strings.Contains(uri, "secret="+secret) {
		t.Errorf("otpauth uri malformed: %s", uri)
	}
	t.Logf("[IMP:8][TestTOTP][GEN] secret len=%d code=%s", len(secret), code)
}
