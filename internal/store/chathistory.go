// Package store — server-side AI chat history (ONE conversation shared by web + Telegram).
//
// region MODULE_CONTRACT [DOMAIN(8): AI,Storage; CONCEPT(8): SharedChatHistory; TECH(7): SQLite]
// @purpose Persist the single AI conversation so both frontends (web ChatPanel and the Telegram
//
//	bridge) read and append the SAME thread — a dialog started in the web UI continues in
//	Telegram with full context, and vice versa. Replaces the client-side localStorage history
//	(web) and the per-chat RAM buffer (tgchat).
//
// @invariants
//   - Only completed turns are stored: exactly one user row + one assistant row per turn.
//   - The table is bounded: after every append the newest chatHistoryCap messages remain.
//   - ClearChatMessages empties the conversation (the "clear chat" button in both frontends).
//
// @rationale
// Q: One global thread instead of per-frontend/per-chat threads?
// A: VM Pulse is a single-operator control room; the "sessions" problem the user reported is
//
//	exactly what per-frontend histories create. One server-owned thread is the simplest model
//	that makes every frontend a thin client.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: ai chat history, shared conversation, append turn, trim, clear, telegram web
// STRUCTURE: ▶ AppendChatTurn: ┌user+assistant┐ → ⊕ INSERT×2 → ∑ trim>200 → ⎋ ; List: SELECT … ORDER BY id DESC LIMIT n → ⊕ reverse
package store

import (
	"context"
	"fmt"
)

// chatHistoryCap bounds the stored conversation (newest N messages kept).
const chatHistoryCap = 200

// ChatMessage is one stored conversation message.
type ChatMessage struct {
	ID      int64  `json:"id"`
	Role    string `json:"role"` // user | assistant
	Content string `json:"content"`
	TS      string `json:"ts"`
}

// region FUNC_AppendChatTurn [DOMAIN(8): AI,Storage; CONCEPT(7): AppendTurn; TECH(7): SQLite]
// @purpose Persist one completed turn (user question + assistant answer) and trim the log.
// @complexity 4
// endregion FUNC_AppendChatTurn
func (s *Store) AppendChatTurn(ctx context.Context, user, assistant string) error {
	if user == "" && assistant == "" {
		return nil
	}
	if _, err := s.DB.ExecContext(ctx, `INSERT INTO ai_chat_messages (role, content) VALUES ('user',?), ('assistant',?)`,
		user, assistant); err != nil {
		return fmt.Errorf("AppendChatTurn: %w", err)
	}
	// Keep only the newest chatHistoryCap rows (id-based trim; the AUTOINCREMENT id is monotonic).
	_, _ = s.DB.ExecContext(ctx, `DELETE FROM ai_chat_messages WHERE id <= (
		SELECT MAX(id) FROM ai_chat_messages) - ?`, chatHistoryCap)
	return nil
}

// region FUNC_ListChatMessages [DOMAIN(8): AI,Storage; CONCEPT(6): Read; TECH(6): SQLite]
// @purpose Return the newest `limit` messages in chronological order (oldest first) — ready to
//
//	feed directly as agent history.
//
// @complexity 3
// endregion FUNC_ListChatMessages
func (s *Store) ListChatMessages(ctx context.Context, limit int) ([]ChatMessage, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id, role, content, ts FROM ai_chat_messages ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("ListChatMessages: %w", err)
	}
	defer rows.Close()
	var out []ChatMessage
	for rows.Next() {
		var m ChatMessage
		if err := rows.Scan(&m.ID, &m.Role, &m.Content, &m.TS); err != nil {
			return nil, fmt.Errorf("ListChatMessages scan: %w", err)
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Reverse into chronological order.
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out, nil
}

// region FUNC_ClearChatMessages [DOMAIN(8): AI,Storage; CONCEPT(6): Clear; TECH(5): SQLite]
// @purpose Empty the shared conversation (the clear-chat button in either frontend).
// @complexity 2
// endregion FUNC_ClearChatMessages
func (s *Store) ClearChatMessages(ctx context.Context) error {
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM ai_chat_messages`); err != nil {
		return fmt.Errorf("ClearChatMessages: %w", err)
	}
	return nil
}
