// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8]: Settings; TECH(8]: go test]
// @purpose Verify settings encryption (is_secret), AI config round-trip, and that secret values
//
//	never appear in the stored column.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, settings, encryption, is_secret, AI config, round-trip
package store

import (
	"context"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/crypto"
)

func armVault(t *testing.T, s *Store) {
	t.Helper()
	salt, _ := crypto.GenerateSalt()
	s.SetVault(crypto.NewVault("passphrase", salt))
}

func TestSettings_SecretEncryption(t *testing.T) {
	s, _ := openTestStore(t)
	armVault(t, s)
	ctx := context.Background()

	_ = s.SetSetting(ctx, "plain", "hello", false)
	_ = s.SetSetting(ctx, "secret", "topsecret", true)

	var raw string
	var isec int
	_ = s.DB.QueryRow(`SELECT value, is_secret FROM settings WHERE key='secret'`).Scan(&raw, &isec)
	if !strings.HasPrefix(raw, "enc:v1:") {
		t.Fatalf("secret must be encrypted at rest, got %q", raw)
	}
	if strings.Contains(raw, "topsecret") {
		t.Fatal("plaintext leaked into stored secret")
	}

	if v, _ := s.GetSetting(ctx, "plain"); v != "hello" {
		t.Fatalf("plain read mismatch: %q", v)
	}
	if v, _ := s.GetSetting(ctx, "secret"); v != "topsecret" {
		t.Fatalf("secret decrypt mismatch: %q", v)
	}
	if has, _ := s.HasSetting(ctx, "plain"); !has {
		t.Fatal("HasSetting plain want true")
	}
	if has, _ := s.HasSetting(ctx, "nope"); has {
		t.Fatal("HasSetting nope want false")
	}
}

func TestAIConfig_RoundTripEncrypted(t *testing.T) {
	s, _ := openTestStore(t)
	armVault(t, s)
	ctx := context.Background()

	_ = s.SetAIConfig(ctx, AIConfig{APIURL: "https://api", APIKey: "sk-test", Model: "gpt"})
	cfg, _ := s.GetAIConfig(ctx)
	if cfg.APIKey != "sk-test" || !cfg.Configured() {
		t.Fatalf("AI config round-trip failed: %+v", cfg)
	}
	var raw string
	_ = s.DB.QueryRow(`SELECT value FROM settings WHERE key=?`, SettingAIAPIKey).Scan(&raw)
	if strings.Contains(raw, "sk-test") || !strings.HasPrefix(raw, "enc:v1:") {
		t.Fatalf("ai.api_key must be encrypted at rest, got %q", raw)
	}
}
