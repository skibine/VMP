// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: LLM; TECH(8]: go test,httptest]
// @purpose Verify OpenAIProvider builds the right request (model/messages/tools, Bearer) and
//
//	parses content + tool_calls from the response.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, provider, OpenAI, httptest, chat completions, tool_calls
// STRUCTURE: ▶ ┌httptest┐ → ○ Chat → 〈path/body/parse?〉 → ⎋ assert
package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOpenAIProvider_ChatParses(t *testing.T) {
	var gotPath, gotAuth string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"hello","tool_calls":[
			{"id":"call_1","type":"function","function":{"name":"list_vms","arguments":"{}"}}]}}]}`))
	}))
	defer srv.Close()

	p := &OpenAIProvider{APIURL: srv.URL, APIKey: "sk-test"}
	resp, err := p.Chat(context.Background(), ChatRequest{
		Model:    "gpt-4o-mini",
		Messages: []Message{{Role: "user", Content: "hi"}},
		Tools:    []Tool{{Name: "list_vms", Description: "list", Parameters: map[string]any{"type": "object"}}},
	})
	if err != nil {
		t.Fatalf("Chat: %v", err)
	}
	if gotPath != "/chat/completions" {
		t.Fatalf("path want /chat/completions, got %s", gotPath)
	}
	if gotAuth != "Bearer sk-test" {
		t.Fatalf("auth want Bearer sk-test, got %s", gotAuth)
	}
	if gotBody["model"] != "gpt-4o-mini" {
		t.Fatalf("model mismatch: %v", gotBody["model"])
	}
	if resp.Content != "hello" {
		t.Fatalf("content want hello, got %s", resp.Content)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Function.Name != "list_vms" {
		t.Fatalf("tool_calls mismatch: %+v", resp.ToolCalls)
	}
}

func TestOpenAIProvider_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad key"}`))
	}))
	defer srv.Close()
	p := &OpenAIProvider{APIURL: srv.URL, APIKey: "bad"}
	_, err := p.Chat(context.Background(), ChatRequest{Model: "m", Messages: []Message{{Role: "user", Content: "x"}}})
	if err == nil {
		t.Fatal("expected error on 401")
	}
}

// region FUNC_test_MessageContentAlwaysPresent [DOMAIN(7): Testing; CONCEPT(8): Wire; TECH(5): json]
// @purpose An assistant tool_calls message has empty text content; that must still serialize as
// @purpose `"content":""` — never omitted (Ollama's OpenAI-compat rejects an absent content as
// @purpose `invalid message content type: <nil>`). Regression for the tool-calling 400.
// @complexity 3
// endregion FUNC_test_MessageContentAlwaysPresent
func TestMessageContentAlwaysPresent(t *testing.T) {
	msg := Message{Role: "assistant", ToolCalls: []ToolCall{
		{ID: "call_1", Type: "function", Function: FunctionCall{Name: "list_vms", Arguments: "{}"}},
	}}
	raw, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	content, ok := m["content"]
	if !ok {
		t.Fatalf("assistant tool_calls message must include content, got: %s", raw)
	}
	if _, isStr := content.(string); !isStr {
		t.Errorf("content must be a string, got %T (%s)", content, raw)
	}
	t.Logf("[IMP:8][TestMsgContent][RESULT] content present as string: %s", raw)
}
