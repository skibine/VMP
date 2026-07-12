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
