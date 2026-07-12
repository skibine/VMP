// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(9]: Crypto; TECH(8]: go test]
// @purpose Verify AES-256-GCM round-trip, marker, random nonce, wrong-passphrase failure,
//
//	and disabled-vault passthrough (incl. encrypted-but-disabled error).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, vault, crypto, round-trip, wrong passphrase, disabled, marker
// STRUCTURE: ▶ ┌salt+pass┐ → ○ NewVault → ⊕ EncryptString → ○ DecryptString → 〈eq?〉 → ⎋
package crypto

import (
	"strings"
	"testing"
)

func TestVault_RoundTripAndMarker(t *testing.T) {
	salt, _ := GenerateSalt()
	v := NewVault("correct horse battery staple", salt)
	if !v.Armed() {
		t.Fatal("vault should be armed with a passphrase + salt")
	}
	plain := `{"bot_token":"123:ABC","chat_id":"42"}`
	enc, err := v.EncryptString(plain)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(enc, "enc:v1:") {
		t.Fatalf("encrypted value must carry the marker, got %q", enc)
	}
	if strings.Contains(enc, "bot_token") {
		t.Fatal("plaintext leaked into the encrypted value")
	}
	dec, err := v.DecryptString(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec != plain {
		t.Fatalf("round-trip mismatch: %q != %q", dec, plain)
	}
	// Random nonce: two encryptions of the same value differ.
	enc2, _ := v.EncryptString(plain)
	if enc == enc2 {
		t.Fatal("two encryptions of the same value should differ (random nonce)")
	}
}

func TestVault_WrongPassphraseFails(t *testing.T) {
	salt, _ := GenerateSalt()
	v1 := NewVault("right", salt)
	v2 := NewVault("wrong", salt)
	enc, _ := v1.EncryptString("secret")
	if _, err := v2.DecryptString(enc); err == nil {
		t.Fatal("decrypt with the wrong passphrase must fail")
	}
}

func TestVault_DisabledPassthrough(t *testing.T) {
	v := NewVault("", nil) // disabled
	if v.Armed() {
		t.Fatal("empty passphrase vault must not be armed")
	}
	enc, err := v.EncryptString("plain")
	if err != nil || enc != "plain" {
		t.Fatalf("disabled encrypt should passthrough, got %q err %v", enc, err)
	}
	dec, err := v.DecryptString("plain")
	if err != nil || dec != "plain" {
		t.Fatalf("disabled decrypt of plaintext should passthrough, got %q err %v", dec, err)
	}
}

func TestVault_DisabledButEncryptedIsError(t *testing.T) {
	v := NewVault("", nil)
	if _, err := v.DecryptString("enc:v1:AAAA"); err == nil {
		t.Fatal("decrypting an encrypted value with a disabled vault must error")
	}
}

func TestVault_EmptySaltDisarms(t *testing.T) {
	v := NewVault("passphrase", nil)
	if v.Armed() {
		t.Fatal("vault must not arm without a salt")
	}
}
