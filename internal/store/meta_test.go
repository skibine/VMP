// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8]: AtRest; TECH(8]: go test]
// @purpose Verify (1) config_meta get/set/upsert, (2) channel config is encrypted at rest yet
//
//	transparently decrypted on read when the vault is armed, (3) disabled vault keeps
//	plaintext (backward compatible).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, config_meta, GetMeta, SetMeta, channel, encrypt at rest, transparent read
// STRUCTURE: ▶ ┌armed store┐ → ⊕ CreateChannel → ○ raw column (enc?) / GetChannel (plain?) → ⎋
package store

import (
	"context"
	"strings"
	"testing"

	"github.com/skibine/vmp/internal/crypto"
)

func TestMeta_GetSetUpsert(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	if _, ok, _ := s.GetMeta(ctx, "vault_salt"); ok {
		t.Fatal("new store should have no vault_salt")
	}
	if err := s.SetMeta(ctx, "k", "v"); err != nil {
		t.Fatal(err)
	}
	got, ok, _ := s.GetMeta(ctx, "k")
	if !ok || got != "v" {
		t.Fatalf("GetMeta want v, got %q ok=%v", got, ok)
	}
	if err := s.SetMeta(ctx, "k", "v2"); err != nil {
		t.Fatal(err)
	}
	got, _, _ = s.GetMeta(ctx, "k")
	if got != "v2" {
		t.Fatalf("upsert want v2, got %q", got)
	}
}

func TestChannelConfig_EncryptedAtRest(t *testing.T) {
	s, buf := openTestStore(t)
	salt, _ := crypto.GenerateSalt()
	s.SetVault(crypto.NewVault("master-pass", salt))
	ctx := context.Background()

	cid, err := s.CreateChannel(ctx, Channel{
		Type:    "telegram",
		Name:    "tg",
		Config:  map[string]any{"bot_token": "123:SECRET", "chat_id": "42"},
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}

	// At rest: the raw column is encrypted and does not leak the token.
	var raw string
	if err := s.DB.QueryRow(`SELECT config FROM channels WHERE id=?`, cid).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(raw, "enc:v1:") {
		t.Fatalf("at rest must be encrypted, got %q", raw)
	}
	if strings.Contains(raw, "SECRET") {
		t.Fatal("plaintext secret leaked into the stored value")
	}

	// Transparent read: GetChannel / ListChannels return the decrypted config.
	ch, err := s.GetChannel(ctx, cid)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Config["bot_token"] != "123:SECRET" {
		t.Fatalf("decrypted bot_token mismatch: %v", ch.Config["bot_token"])
	}
	list, _ := s.ListChannels(ctx)
	// A fresh store auto-seeds a built-in "in-app" channel, so find the telegram one explicitly.
	var tg *Channel
	for i := range list {
		if list[i].Type == "telegram" {
			tg = &list[i]
		}
	}
	if tg == nil || tg.Config["chat_id"] != "42" {
		t.Fatalf("ListChannels decrypt mismatch: %+v", list)
	}

	printIMPFromBuf(t, buf)
}

func TestChannelConfig_DisabledKeepsPlaintext(t *testing.T) {
	s, _ := openTestStore(t) // no SetVault -> disabled
	ctx := context.Background()
	cid, _ := s.CreateChannel(ctx, Channel{Type: "log", Name: "d", Config: map[string]any{"k": "v"}})

	var raw string
	_ = s.DB.QueryRow(`SELECT config FROM channels WHERE id=?`, cid).Scan(&raw)
	if strings.HasPrefix(raw, "enc:v1:") {
		t.Fatal("disabled vault must store plaintext, not encrypted")
	}
	ch, _ := s.GetChannel(ctx, cid)
	if ch.Config["k"] != "v" {
		t.Fatalf("disabled read mismatch: %v", ch.Config["k"])
	}
}
