// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): SharedChatHistory; TECH(8): go test,httptest]
// @purpose Verify the SERVER-side chat history: a second /api/ai/chat turn receives the first
//
//	turn as context (the provider sees it), GET /api/ai/history renders it, DELETE clears it.
//	This is the web<->Telegram shared-conversation contract.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, ai history, shared conversation, chat endpoint, httptest, clear
// STRUCTURE: ▶ ┌server+recording agent┐ → ⚡ turn1 → ⚡ turn2 → 〈history seen?〉 → ⚡ DELETE → ⎋
package api

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/skibine/vmp/internal/ai"
)

// echoHistoryProvider echoes back the last user message it SAW in history (proves context flow).
type echoHistoryProvider struct {
	mu    sync.Mutex
	turns [][]string // user messages visible per provider call
}

func (p *echoHistoryProvider) Chat(_ context.Context, req ai.ChatRequest) (ai.ChatResponse, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	var userMsgs []string
	for _, m := range req.Messages {
		if m.Role == "user" {
			userMsgs = append(userMsgs, m.Content)
		}
	}
	p.turns = append(p.turns, userMsgs)
	return ai.ChatResponse{Content: "echo:" + userMsgs[len(userMsgs)-1]}, nil
}

func TestHTTP_AIChat_ServerHistoryShared(t *testing.T) {
	srv, buf := newServer(t)
	prov := &echoHistoryProvider{}
	srv.WithAgent(&ai.Agent{Provider: prov, Tools: ai.NewRegistry(), Model: "m", Logger: srv.logger})

	// Turn 1: fresh conversation — the provider sees only this message.
	rec := do(srv, http.MethodPost, "/api/ai/chat", `{"message":"что с web1?"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "echo:что с web1?") {
		t.Fatalf("turn1 failed: %d %s", rec.Code, rec.Body.String())
	}

	// Turn 2: client sends EMPTY history (Telegram case) — the provider must still see turn 1's
	// user message in its context, because history comes from the server store.
	rec = do(srv, http.MethodPost, "/api/ai/chat", `{"message":"а теперь домены?"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("turn2 failed: %d %s", rec.Code, rec.Body.String())
	}
	prov.mu.Lock()
	turns := prov.turns
	prov.mu.Unlock()
	if len(turns) != 2 {
		t.Fatalf("want 2 provider calls, got %d", len(turns))
	}
	// The SECOND call must include BOTH user messages — proof the server appended turn 1.
	if len(turns[1]) != 2 || turns[1][0] != "что с web1?" || turns[1][1] != "а теперь домены?" {
		t.Fatalf("turn2 context missing turn1 (shared history broken): %v", turns)
	}

	// GET /api/ai/history renders all 4 messages (2 turns x user+assistant), oldest first.
	rec = do(srv, http.MethodGet, "/api/ai/history", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("history GET failed: %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"что с web1?", "echo:что с web1?", "а теперь домены?", "echo:а теперь домены?"} {
		if !strings.Contains(body, want) {
			t.Fatalf("history missing %q: %s", want, body)
		}
	}
	if strings.Index(body, "что с web1?") > strings.Index(body, "а теперь домены?") {
		t.Fatalf("history not chronological: %s", body)
	}

	// DELETE clears; next turn starts fresh.
	rec = do(srv, http.MethodDelete, "/api/ai/history", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("history DELETE failed: %d", rec.Code)
	}
	rec = do(srv, http.MethodGet, "/api/ai/history", "")
	if strings.Contains(rec.Body.String(), "web1") {
		t.Fatalf("history not cleared: %s", rec.Body.String())
	}
	rec = do(srv, http.MethodPost, "/api/ai/chat", `{"message":"fresh start"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("post-clear turn failed: %d", rec.Code)
	}
	prov.mu.Lock()
	allTurns := prov.turns
	prov.mu.Unlock()
	last := allTurns[len(allTurns)-1]
	if len(last) != 1 || last[0] != "fresh start" {
		t.Fatalf("post-clear context still polluted: %v", last)
	}

	t.Logf("[IMP:8][TestAIHistory][RESULT] shared turns=2 history=4 cleared=fresh")
	printIMPFromBuf(t, buf)
}
