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
	"errors"
	"net/http"

	"github.com/skibine/vm-pulse/internal/ai"
	"github.com/skibine/vm-pulse/internal/logging"
)

// region FUNC_aiChat [DOMAIN(8): AI; CONCEPT(7): Handler; TECH(7): net/http]
// @purpose Handle one copilot turn.
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
		History []ai.Message `json:"history"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Message == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "message required"})
		return
	}
	reply, err := s.agent.Ask(r.Context(), body.Message, body.History)
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
	writeJSON(w, http.StatusOK, map[string]any{"reply": reply.Reply, "trace": reply.Trace})
}
