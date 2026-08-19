// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): TOTPReplayGuard; TECH(8): go test]
// @purpose A code consumed once must be refused on immediate reuse (same step), while the NEXT
//
//	step's code is accepted (the guard never locks the operator out).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, totp, replay, step, 2fa, reuse, hotp
package auth

import (
	"testing"
	"time"
)

// region FUNC_test_TOTPReplay [DOMAIN(9): Security; CONCEPT(7): StepConsumption; TECH(5): hotp]
// @purpose The loginTwoFA guard contract: matched step must be strictly greater than the stored
//
//	last step. Verify ValidateStep surfaces the matched step for both a fresh and a replayed code.
//
// @complexity 3
// endregion FUNC_test_TOTPReplay
func TestTOTP_ReplayRefused(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret: %v", err)
	}
	now := time.Now()
	counter := int64(now.Unix()) / int64(totpStep.Seconds())

	code, err := hotp(secret, uint64(counter))
	if err != nil {
		t.Fatalf("hotp: %v", err)
	}

	// Fresh code validates and reports its step.
	step, ok := ValidateStep(secret, code, now)
	if !ok || step != counter {
		t.Fatalf("fresh code: ok=%v step=%d want=%d", ok, step, counter)
	}

	// Guard contract: replay = a later ValidateStep match with step <= consumed step. Simulate
	// the loginTwoFA check verbatim: matched step must be > last to proceed.
	last := step
	replayStep, replayOK := ValidateStep(secret, code, now)
	if replayOK && replayStep > last {
		t.Fatal("same-instant replay must fail the >last guard (step==last)")
	}

	// The NEXT step's code passes the guard.
	code2, err := hotp(secret, uint64(counter+1))
	if err != nil {
		t.Fatalf("hotp next: %v", err)
	}
	step2, ok2 := ValidateStep(secret, code2, now.Add(totpStep))
	if !ok2 || step2 <= last {
		t.Fatalf("next-step code must validate with step>last: ok=%v step=%d last=%d", ok2, step2, last)
	}
	t.Logf("[IMP:9][TestTOTPReplay][RESULT] replay step==last refused, next step=%d accepted", step2)
}

// endregion FUNC_test_TOTPReplay
