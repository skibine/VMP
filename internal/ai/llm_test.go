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
