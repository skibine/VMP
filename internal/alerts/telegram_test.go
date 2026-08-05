// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: Telegram; TECH(8]: go test,httptest]
// @purpose Verify TelegramChannel delivery against a local httptest server + error cases.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, telegram, channel, httptest, sendMessage, bot_token
// STRUCTURE: ▶ ┌httptest┐ → ○ Deliver(api_url=server) → 〈2xx? err?〉 → ⎋ assert
package alerts

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestTelegramChannel_Deliver(t *testing.T) {
	var gotPath, gotBody string
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()

	ch := &TelegramChannel{}
	err := ch.Deliver(context.Background(), map[string]any{
		"bot_token": "123:ABC", "chat_id": "42", "api_url": srv.URL,
	}, Message{Severity: "critical", RuleName: "down", CheckType: "tcp", CheckID: 7, Title: "tcp is critical", Body: "status=critical"})
	if err != nil {
		t.Fatalf("Deliver: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(gotPath, "/bot123:ABC/sendMessage") {
		t.Fatalf("unexpected path: %s", gotPath)
	}
	if !strings.Contains(gotBody, "chat_id=42") || !strings.Contains(gotBody, "tcp+is+critical") || !strings.Contains(gotBody, "VM+Pulse+CRITICAL") {
		t.Fatalf("unexpected body: %s", gotBody)
	}
}

func TestTelegramChannel_Errors(t *testing.T) {
	ch := &TelegramChannel{}
	// Missing token/chat.
	if err := ch.Deliver(context.Background(), map[string]any{"chat_id": "1"}, Message{}); err == nil {
		t.Fatal("expected error for missing bot_token")
	}
	// Non-2xx response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"ok":false}`))
	}))
	defer srv.Close()
	err := ch.Deliver(context.Background(), map[string]any{
		"bot_token": "t", "chat_id": "1", "api_url": srv.URL,
	}, Message{Title: "x", Body: "y"})
	if err == nil || !strings.Contains(err.Error(), "status 400") {
		t.Fatalf("expected status-400 error, got %v", err)
	}
}

// region FUNC_test_ResolveChatID [DOMAIN(7): Testing; CONCEPT(8): Onboarding; TECH(8): httptest]
// @purpose Verify chat_id auto-capture: getUpdates is parsed correctly and the last message's chat
// @purpose id is returned; empty result yields a helpful error.
// @complexity 3
// endregion FUNC_test_ResolveChatID
func TestResolveTelegramChatID(t *testing.T) {
	// Server returns one update carrying a message with chat.id=42424242.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/getUpdates") {
			t.Errorf("expected getUpdates path, got %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"result":[{"update_id":1,"message":{"message_id":9,"chat":{"id":42424242,"first_name":"alex"},"text":"/start"}}]}`))
	}))
	defer srv.Close()

	id, err := ResolveTelegramChatID(context.Background(), "123:ABC", srv.URL)
	if err != nil {
		t.Fatalf("ResolveTelegramChatID: %v", err)
	}
	if id != "42424242" {
		t.Fatalf("expected chat_id 42424242, got %s", id)
	}
	t.Logf("[IMP:8][TestResolveChatID][RESULT] captured chat_id=%s", id)

	// Empty result -> friendly error (operator hasn't messaged the bot yet).
	empty := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"ok":true,"result":[]}`))
	}))
	defer empty.Close()
	if _, err := ResolveTelegramChatID(context.Background(), "123:ABC", empty.URL); err == nil {
		t.Fatal("expected error when no messages are present")
	}
}

// region FUNC_test_RedactToken [DOMAIN(8): Testing; CONCEPT(9): SecretHygiene; TECH(7): regexp]
// @purpose Verify a transport failure never leaks the bot token: net/http's *url.Error embeds the
// @purpose full /bot<TOKEN>/... URL, which must be scrubbed from the returned (and logged) error.
// @complexity 2
// endregion FUNC_test_RedactToken
func TestResolveTelegramChatID_RedactsToken(t *testing.T) {
	// Point at a closed port so client.Do returns a url.Error carrying the token-bearing URL.
	_, err := ResolveTelegramChatID(context.Background(), "777777:SECRETsecretSECRET", "http://127.0.0.1:1")
	if err == nil {
		t.Fatal("expected a transport error")
	}
	if strings.Contains(err.Error(), "777777:SECRETsecretSECRET") || strings.Contains(err.Error(), "SECRETsecret") {
		t.Fatalf("bot token leaked into error: %s", err.Error())
	}
	t.Logf("[IMP:9][TestRedactToken][RESULT] error=%s", err.Error())
}
