// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8]: SettingsProvider; TECH(8]: go test,httptest]
// @purpose Verify SettingsProvider returns ErrNotConfigured when AI is unset and delegates to a
//
//	real provider once configured (via httptest).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, SettingsProvider, ErrNotConfigured, httptest
package ai

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skibine/vm-pulse/internal/store"
)

func TestSettingsProvider_NotConfigured(t *testing.T) {
	s := newAIStore(t)
	sp := &SettingsProvider{Store: s}
	_, err := sp.Chat(context.Background(), ChatRequest{})
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}

func TestSettingsProvider_DelegatesWhenConfigured(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hi there"}}]}`))
	}))
	defer srv.Close()

	s := newAIStore(t)
	ctx := context.Background()
	_ = s.SetAIConfig(ctx, store.AIConfig{APIURL: srv.URL, APIKey: "sk", Model: "m"})

	sp := &SettingsProvider{Store: s}
	resp, err := sp.Chat(ctx, ChatRequest{Messages: []Message{{Role: "user", Content: "ping"}}})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if resp.Content != "hi there" {
		t.Fatalf("unexpected content: %q", resp.Content)
	}
}
