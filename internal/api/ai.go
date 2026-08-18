// Package api — AI copilot chat endpoint.
//
// region MODULE_CONTRACT [DOMAIN(8): AI; CONCEPT(7): Endpoint; TECH(8): net/http]
// @purpose Expose the AI agent as POST /api/ai/chat. Returns 503 when AI is not configured
//
//	(no api_key). v0: read-only tools only; TODO(auth): gate with Plane B middleware.
//
// @invariants
//   - A nil agent (AI disabled) always yields 503, never a panic.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: ai, chat, endpoint, copilot, 503, agent
// STRUCTURE: ▶ ┌{message,history}┐ → 〈agent? 503〉 → ○ Ask → ⊕ {reply} → ⎷ JSON
package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/skibine/vm-pulse/internal/ai"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// region FUNC_aiChat [DOMAIN(8): AI; CONCEPT(7): Handler; TECH(7): net/http]
// @purpose Handle one copilot turn. History is SERVER-side (shared with the Telegram bridge):
//
//	the client-sent history field is ignored for context purposes (kept in the request shape for
//	compatibility) — the last 50 stored messages are loaded, the new turn appended after the
//	answer. This makes web and Telegram one continuous conversation.
//
// @complexity 4
// endregion FUNC_aiChat
func (s *Server) aiChat(w http.ResponseWriter, r *http.Request) {
	if s.agent == nil {
		logging.LDD(s.logger, 7, "aiChat", "DISABLED", "ai not configured")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ai not configured"})
		return
	}
	var body struct {
		Message string       `json:"message"`
		History []ai.Message `json:"history"` // deprecated: server-side history is authoritative
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Message == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message required"})
		return
	}
	history := s.chatHistory(r.Context())
	watermark := s.maxPendingActionID(r.Context()) // pre-turn: pending actions created BY this turn get mirrored
	reply, err := s.agent.Ask(r.Context(), body.Message, history)
	if err != nil {
		if errors.Is(err, ai.ErrNotConfigured) {
			logging.LDD(s.logger, 7, "aiChat", "DISABLED", "ai not configured")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "ai not configured"})
			return
		}
		logging.LDD(s.logger, 10, "aiChat", "ASK_FAIL", err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "ai: " + err.Error()})
		return
	}
	// Persist the completed turn so the OTHER frontend (Telegram) sees it too.
	_ = s.store.AppendChatTurn(r.Context(), body.Message, reply.Reply)
	// Push the turn to the telegram bridge (web->telegram half of the shared conversation) so the
	// operator reads the web chat in telegram without refreshing. Async + bounded: the HTTP
	// response never waits on telegram, and no telegram config => chatMirror is nil => no-op.
	if s.chatMirror != nil {
		go func(user, assistant string, wm int64) {
			mctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			s.chatMirror.MirrorWebTurn(mctx, user, assistant, wm)
		}(body.Message, reply.Reply, watermark)
	}
	writeJSON(w, http.StatusOK, map[string]any{"reply": reply.Reply, "trace": reply.Trace})
}

// maxPendingActionID returns the highest ai_action id (0 on error/none) — the pre-turn watermark
// the chat mirror uses to announce only actions proposed during the mirrored turn.
func (s *Server) maxPendingActionID(ctx context.Context) int64 {
	actions, err := s.store.ListAIActions(ctx, "")
	if err != nil || len(actions) == 0 {
		return 0
	}
	return actions[0].ID
}

// chatHistory loads the shared conversation as agent history (nil-safe on store errors).
func (s *Server) chatHistory(ctx context.Context) []ai.Message {
	msgs, err := s.store.ListChatMessages(ctx, 50)
	if err != nil {
		logging.LDD(s.logger, 8, "aiChat", "HISTORY_FAIL", err.Error())
		return nil
	}
	out := make([]ai.Message, 0, len(msgs))
	for _, m := range msgs {
		if m.Role == "user" || m.Role == "assistant" {
			out = append(out, ai.Message{Role: m.Role, Content: m.Content})
		}
	}
	return out
}

// aiHistory returns the shared conversation for UI rendering (newest 100, oldest first).
func (s *Server) aiHistory(w http.ResponseWriter, r *http.Request) {
	msgs, err := s.store.ListChatMessages(r.Context(), 100)
	if err != nil {
		logging.LDD(s.logger, 10, "aiHistory", "FAIL", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if msgs == nil {
		msgs = []store.ChatMessage{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"messages": msgs})
}

// aiHistoryClear empties the shared conversation (web "clear" button; Telegram starts fresh too).
func (s *Server) aiHistoryClear(w http.ResponseWriter, r *http.Request) {
	if err := s.store.ClearChatMessages(r.Context()); err != nil {
		logging.LDD(s.logger, 10, "aiHistoryClear", "FAIL", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}
