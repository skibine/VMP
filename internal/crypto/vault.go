// Package crypto implements the credential vault: AES-256-GCM authenticated encryption of
// secrets at rest, keyed by an argon2id-derived key from a master passphrase.
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): AtRestEncryption; TECH(9): AES-256-GCM,argon2]
// @purpose Keep secrets (channel tokens, later SSH creds) unreadable on a stolen DB file. The
//
//	master passphrase is NOT stored; only a salt is persisted (in config_meta by callers).
//
// @io NewVault(passphrase, salt) -> *Vault ; EncryptString/DecryptString for DB columns.
// @invariants
//   - A nil or disabled Vault is a transparent passthrough (plaintext in, plaintext out).
//   - Encrypted values carry the literal marker "enc:v1:" so readers distinguish them.
//   - The passphrase is never serialized or returned by any Vault method.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: vault, crypto, AES-256-GCM, argon2id, encrypt, decrypt, secret, at rest, enc:v1
// STRUCTURE: ▶ ┌passphrase+salt┐ → ⚡ argon2id → ⊕ key → ○ AES-GCM(nonce+ct) → ⊕ "enc:v1:"+b64 → ⎷
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	marker    = "enc:v1:" // DB-column prefix identifying an encrypted value
	saltLen   = 16
	keyLen    = 32 // AES-256
	argonTime = 1
	argonMem  = 64 * 1024
	argonPar  = 4
)

// region STRUCT_Vault [DOMAIN(9): Security; CONCEPT(7): Keyring; TECH(8): AES-GCM]
// @purpose Hold the derived key (nil when disabled) and encrypt/decrypt column values.
// endregion STRUCT_Vault
type Vault struct {
	key []byte // nil when disabled (passthrough)
}

// region FUNC_NewVault [DOMAIN(9): Security; CONCEPT(7): Arm; TECH(8): argon2id]
// @purpose Derive an AES-256 key from a passphrase+salt. Empty passphrase -> disabled vault.
// @complexity 3
// endregion FUNC_NewVault
func NewVault(passphrase string, salt []byte) *Vault {
	if strings.TrimSpace(passphrase) == "" {
		return &Vault{}
	}
	if len(salt) == 0 {
		return &Vault{} // refuse to arm without a salt (callers must generate one)
	}
	return &Vault{key: argon2.IDKey([]byte(passphrase), salt, argonTime, argonMem, argonPar, keyLen)}
}

// Armed reports whether the vault will actually encrypt (key present).
func (v *Vault) Armed() bool { return v != nil && len(v.key) == keyLen }

// region FUNC_Vault_Encrypt [DOMAIN(9): Security; CONCEPT(7): Encrypt; TECH(8): AES-GCM]
// @purpose Encrypt plaintext with a random nonce prepended to the ciphertext.
// @complexity 4
// endregion FUNC_Vault_Encrypt
func (v *Vault) Encrypt(plaintext []byte) ([]byte, error) {
	if !v.Armed() {
		return plaintext, nil
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, fmt.Errorf("vault: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("vault: nonce: %w", err)
	}
	// Seal appends ciphertext+tag to the nonce.
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// region FUNC_Vault_Decrypt [DOMAIN(9): Security; CONCEPT(7): Decrypt; TECH(8): AES-GCM]
// @purpose Decrypt a nonce-prepended ciphertext blob.
// @complexity 4
// endregion FUNC_Vault_Decrypt
func (v *Vault) Decrypt(blob []byte) ([]byte, error) {
	if !v.Armed() {
		return blob, nil
	}
	block, err := aes.NewCipher(v.key)
	if err != nil {
		return nil, fmt.Errorf("vault: cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("vault: gcm: %w", err)
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, errors.New("vault: ciphertext too short")
	}
	return gcm.Open(nil, blob[:ns], blob[ns:], nil)
}

// region FUNC_Vault_EncryptString [DOMAIN(9): Security; CONCEPT(7): ColumnWrite; TECH(7): base64]
// @purpose Encrypt a string for a DB column: "enc:v1:"+base64(nonce+ct). Passthrough when disabled
//
//	or when the vault is not armed.
//
// @complexity 3
// endregion FUNC_Vault_EncryptString
func (v *Vault) EncryptString(s string) (string, error) {
	if !v.Armed() {
		return s, nil
	}
	ct, err := v.Encrypt([]byte(s))
	if err != nil {
		return "", err
	}
	return marker + base64.StdEncoding.EncodeToString(ct), nil
}

// region FUNC_Vault_DecryptString [DOMAIN(9): Security; CONCEPT(7): ColumnRead; TECH(7): base64]
// @purpose Decrypt a column value. Values without the marker pass through (legacy plaintext).
//
//	A marker value with a disabled vault is an error (misconfiguration).
//
// @complexity 3
// endregion FUNC_Vault_DecryptString
func (v *Vault) DecryptString(s string) (string, error) {
	if !strings.HasPrefix(s, marker) {
		return s, nil // plaintext (legacy or disabled-write)
	}
	if !v.Armed() {
		return "", errors.New("vault: value is encrypted but vault is disabled")
	}
	ct, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(s, marker))
	if err != nil {
		return "", fmt.Errorf("vault: decode: %w", err)
	}
	pt, err := v.Decrypt(ct)
	if err != nil {
		return "", fmt.Errorf("vault: decrypt: %w", err)
	}
	return string(pt), nil
}

// GenerateSalt returns a random salt for key derivation.
func GenerateSalt() ([]byte, error) {
	s := make([]byte, saltLen)
	if _, err := rand.Read(s); err != nil {
		return nil, err
	}
	return s, nil
}
