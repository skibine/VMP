// Package store — key/value meta table + vault column glue.
//
// region MODULE_CONTRACT [DOMAIN(8): Storage; CONCEPT(7): MetaKV; TECH(8): database/sql,AES]
// @purpose config_meta get/set (e.g. vault salt) and transparent encrypt/decrypt helpers used
//
//	at the boundary of secret-bearing columns (channels.config).
//
// @invariants
//   - encCol/decCol are no-ops when the vault is disabled (plaintext passthrough).
//   - GetMeta returns ok=false for a missing key (not an error).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: config_meta, GetMeta, SetMeta, vault, encCol, decCol, encrypt, decrypt
// STRUCTURE: ▶ ┌key/value┐ → ○ upsert/select → ⎋ ; encCol → vault.EncryptString
package store

import (
	"context"
	"strings"

	"github.com/skibine/vm-pulse/internal/crypto"
	"github.com/skibine/vm-pulse/internal/logging"
)

// GetMeta reads a value from config_meta; ok=false when the key is absent.
func (s *Store) GetMeta(ctx context.Context, key string) (string, bool, error) {
	var v string
	err := s.DB.QueryRowContext(ctx, `SELECT value FROM config_meta WHERE key=?`, key).Scan(&v)
	if err != nil {
		if isNoRows(err) {
			return "", false, nil
		}
		return "", false, err
	}
	return v, true, nil
}

// SetMeta upserts a key/value into config_meta.
func (s *Store) SetMeta(ctx context.Context, key, value string) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO config_meta (key,value) VALUES (?,?)
		 ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// SetVault arms the at-rest encryption for secret columns. nil disables it.
func (s *Store) SetVault(v *crypto.Vault) { s.vault = v }

// encCol encrypts a plaintext column value when the vault is armed (else passthrough).
func (s *Store) encCol(plain string) string {
	if s.vault == nil || !s.vault.Armed() {
		return plain
	}
	out, err := s.vault.EncryptString(plain)
	if err != nil {
		logging.LDD(s.logger, 10, "encCol", "FAIL", err.Error())
		return plain
	}
	return out
}

// decCol decrypts a column value; marker-less values pass through (legacy plaintext).
func (s *Store) decCol(raw string) string {
	if !strings.HasPrefix(raw, "enc:v1:") {
		return raw
	}
	if s.vault == nil || !s.vault.Armed() {
		logging.LDD(s.logger, 10, "decCol", "ENCRYPTED_BUT_DISABLED", "value is encrypted but vault is disabled")
		return ""
	}
	out, err := s.vault.DecryptString(raw)
	if err != nil {
		logging.LDD(s.logger, 10, "decCol", "FAIL", err.Error())
		return ""
	}
	return out
}
