// Package store — in-app settings (key/value, optionally vault-encrypted).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(7): Settings; TECH(8): database/sql,vault]
// @purpose Store operational config (AI provider, etc.) manageable from the app. Secret values
//
//	are transparently encrypted at the boundary (enc:v1) when the vault is armed.
//
// @invariants
//   - SetSetting with is_secret=true encrypts; GetSetting decrypts. Plaintext settings pass through.
//   - The AI group (api_url/model plain, api_key secret) is the primary consumer this slice.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: settings, GetSetting, SetSetting, HasSetting, AI config, encrypted, vault
// STRUCTURE: ▶ ┌key,value,is_secret┐ → ○ encCol on write / decCol on read → ⎷ value
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// Setting key constants for the AI provider group.
const (
	SettingAIAPIURL = "ai.api_url"
	SettingAIAPIKey = "ai.api_key"
	SettingAIModel  = "ai.model"
)

// SetSetting upserts a setting; when isSecret, the value is vault-encrypted at rest.
func (s *Store) SetSetting(ctx context.Context, key, value string, isSecret bool) error {
	stored := value
	if isSecret {
		stored = s.encCol(value)
	}
	_, err := s.DB.ExecContext(ctx, `
INSERT INTO settings (key, value, is_secret) VALUES (?,?,?)
ON CONFLICT(key) DO UPDATE SET value=excluded.value, is_secret=excluded.is_secret,
 updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')`,
		key, stored, toBoolInt(isSecret))
	if err != nil {
		return fmt.Errorf("SetSetting: %w", err)
	}
	return nil
}

// GetSetting returns the decrypted value for a key (empty string if absent).
func (s *Store) GetSetting(ctx context.Context, key string) (string, error) {
	var raw string
	var isSecret int
	err := s.DB.QueryRowContext(ctx, `SELECT value, is_secret FROM settings WHERE key=?`, key).Scan(&raw, &isSecret)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("GetSetting: %w", err)
	}
	if isSecret != 0 {
		return s.decCol(raw), nil
	}
	return raw, nil
}

// HasSetting reports whether a key exists.
func (s *Store) HasSetting(ctx context.Context, key string) (bool, error) {
	var one int
	err := s.DB.QueryRowContext(ctx, `SELECT 1 FROM settings WHERE key=?`, key).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("HasSetting: %w", err)
	}
	return true, nil
}

// AIConfig is the resolved AI provider configuration read from settings (key decrypted).
type AIConfig struct {
	APIURL string
	APIKey string
	Model  string
}

// Configured reports whether all three AI fields are set.
func (c AIConfig) Configured() bool {
	return c.APIURL != "" && c.APIKey != "" && c.Model != ""
}

// GetAIConfig reads the AI group from settings (decrypting the key).
func (s *Store) GetAIConfig(ctx context.Context) (AIConfig, error) {
	url, err := s.GetSetting(ctx, SettingAIAPIURL)
	if err != nil {
		return AIConfig{}, err
	}
	key, err := s.GetSetting(ctx, SettingAIAPIKey)
	if err != nil {
		return AIConfig{}, err
	}
	model, err := s.GetSetting(ctx, SettingAIModel)
	if err != nil {
		return AIConfig{}, err
	}
	return AIConfig{APIURL: url, APIKey: key, Model: model}, nil
}

// SetAIConfig writes the AI group (api_key encrypted).
func (s *Store) SetAIConfig(ctx context.Context, c AIConfig) error {
	if err := s.SetSetting(ctx, SettingAIAPIURL, c.APIURL, false); err != nil {
		return err
	}
	if err := s.SetSetting(ctx, SettingAIAPIKey, c.APIKey, true); err != nil {
		return err
	}
	return s.SetSetting(ctx, SettingAIModel, c.Model, false)
}
