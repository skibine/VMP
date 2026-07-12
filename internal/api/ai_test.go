// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: AIEndpoint; TECH(8]: go test,httptest]
// @purpose Verify POST /api/ai/chat: 503 when AI disabled, 200 with reply when agent set.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, ai chat, endpoint, 503, agent, httptest
// STRUCTURE: ▶ ┌server┐ → 〈agent? 503 : Ask〉 → ⊕ {reply} → ⎋ assert
package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/ai"
)

// stubProvider always returns a fixed answer.
type stubProvider struct{}

func (stubProvider) Chat(_ context.Context, _ ai.ChatRequest) (ai.ChatResponse, error) {
	return ai.ChatResponse{Content: "all good"}, nil
}

func TestHTTP_AIChat_DisabledThenEnabled(t *testing.T) {
	srv, buf := newServer(t)

	// Disabled (no agent): 503.
	rec := do(srv, http.MethodPost, "/api/ai/chat", `{"message":"hi"}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("disabled want 503, got %d", rec.Code)
	}

	// Attach an agent with a stub provider + no tools (final answer immediately).
	srv.WithAgent(&ai.Agent{Provider: stubProvider{}, Tools: ai.NewRegistry(), Model: "m", Logger: srv.logger})
	rec = do(srv, http.MethodPost, "/api/ai/chat", `{"message":"any alerts?"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("enabled want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "all good") {
		t.Fatalf("reply mismatch: %s", rec.Body.String())
	}

	// Empty message -> 400.
	rec = do(srv, http.MethodPost, "/api/ai/chat", `{"message":""}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty message want 400, got %d", rec.Code)
	}

	printIMPFromBuf(t, buf)
}
