// Package tgchat — poller: the long-poll loop of one bot token.
//
// region MODULE_CONTRACT [DOMAIN(8): AI,Integration; CONCEPT(8): PollLoop; TECH(8): long-poll,http]
// @purpose Drive one bot: skip the backlog on start, then long-poll updates forever, answer allowed
//
//	chats through the shared agent, announce NEW pending actions with ✅/❌ buttons, and resolve
//	button callbacks through the shared approve-path.
//
// @invariants
//   - Updates are processed STRICTLY sequentially (no interleaved Ask calls on one bot).
//   - Messages from chats outside the allowlist are audited (Plane B, suspicious) and never answered.
//   - History is RAM-only (chat is ephemeral): 24 turns per chat, lost on restart by design.
//   - Backlog is skipped on start (offset=-1 preview -> offset=last+1) so a restart never replays
//     hours-old commands into the agent.
//
// @rationale
// Q: Why announce pending actions by id-watermark instead of hooking propose_command?
// A: The ai package must stay transport-agnostic. The poller snapshots max(action id) before the
//
//	Ask call and reports pending rows with a higher id after it — zero coupling, and it also
//	catches proposals made by the web chat in the same window (the chat is a control room).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: poller, getUpdates, long-poll, allowlist, history, typing, watermark, callback, buttons
// STRUCTURE: ▶ ┌skip backlog┐ → ○ loop ⚡getUpdates(25s) → 〈message? ◇allowed → ⚡typing → Ask → ⊕split → sendMessage → ⊕pending>watermark → ✅❌ ; callback → Approver〉 → ⎋
package tgchat

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skibine/vm-pulse/internal/ai"
	"github.com/skibine/vm-pulse/internal/audit"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// Asker is the agent face the bridge needs (implemented by *ai.Agent).
type Asker interface {
	Ask(ctx context.Context, message string, history []ai.Message) (ai.AskReply, error)
}

// Approver executes approved AI actions (implemented by *api.Server; keeps tgchat free of the
// api import — no cycle).
type Approver interface {
	ApproveAIAction(ctx context.Context, id int64, via string) (status, output string, err error)
}

// poller serves ONE bot token with a set of allowed chat ids.
type poller struct {
	api      *botAPI
	allowed  map[string]bool // chat_id (string) -> allowed
	st       *store.Store
	agent    Asker
	approver Approver
	logger   *slog.Logger

	mu       sync.Mutex
	notCfgAt time.Time // last "AI not configured" nag (rate-limited)
}

const (
	maxReplyChunk   = 4000
	announceTrunc   = 3500 // output embedded into an edited announce message
	notConfiguredCD = 10 * time.Minute
)

// region FUNC_poller_run [DOMAIN(8): Integration; CONCEPT(8): LongPoll; TECH(7): net/http]
// @purpose The bot's main loop: skip backlog, then process updates sequentially until ctx ends.
//
//	Transient errors (network, 5xx) sleep briefly; 409 conflicts back off harder (another
//	poller owns the queue — usually the operator testing getUpdates by hand).
//
// @complexity 7
// endregion FUNC_poller_run
func (p *poller) run(ctx context.Context) {
	offset := p.skipBacklog(ctx)
	logging.LDD(p.logger, 7, "tgchat", "POLL_START", "backlog skipped, offset="+strconv.FormatInt(offset, 10))
	for {
		if ctx.Err() != nil {
			return
		}
		updates, err := p.api.getUpdates(ctx, offset, 25)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			backoff := 5 * time.Second
			if IsBotConflict(err) {
				backoff = 30 * time.Second
			}
			logging.LDD(p.logger, 9, "tgchat", "POLL_FAIL", err.Error()+" — retry in "+backoff.String())
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
				return
			}
			continue
		}
		for _, u := range updates {
			offset = u.UpdateID + 1
			p.dispatch(ctx, u)
		}
	}
}

// skipBacklog previews the last update (offset=-1) without confirming, then returns lastID+1 so
// the first real poll confirms everything older — a restart never replays stale commands.
func (p *poller) skipBacklog(ctx context.Context) int64 {
	updates, err := p.api.getUpdates(ctx, -1, 0)
	if err != nil || len(updates) == 0 {
		return 0
	}
	maxID := int64(0)
	for _, u := range updates {
		if u.UpdateID > maxID {
			maxID = u.UpdateID
		}
	}
	return maxID + 1
}

// dispatch routes one update to the message or callback handler.
func (p *poller) dispatch(ctx context.Context, u tgUpdate) {
	switch {
	case u.Message != nil && strings.TrimSpace(u.Message.Text) != "":
		p.handleMessage(ctx, u.Message)
	case u.CallbackQuery != nil:
		p.handleCallback(ctx, u.CallbackQuery)
	}
}

// region FUNC_poller_handleMessage [DOMAIN(8): AI; CONCEPT(8): ChatTurn; TECH(7): agent]
// @purpose One conversational turn: allowlist gate -> typing -> agent.Ask (shared server history) ->
//
//	split reply -> announce NEW pending actions with ✅/❌ buttons.
//
// @complexity 6
// endregion FUNC_poller_handleMessage
func (p *poller) handleMessage(ctx context.Context, msg *tgMessage) {
	chatID := strconv.FormatInt(msg.Chat.ID, 10)
	if !p.allowed[chatID] {
		logging.LDD(p.logger, 9, "tgchat", "DENIED", "chat_id="+chatID+" is not in the channel allowlist")
		_ = audit.Append(p.st.DB, p.logger, audit.Entry{
			Plane: audit.PlaneB, Action: "tg_chat_denied", Success: false,
			Detail: "chat_id=" + chatID + " update_text=" + truncate(msg.Text, 80),
		})
		return
	}

	text := strings.TrimSpace(msg.Text)
	if text == "/start" || text == "/help" {
		p.reply(ctx, chatID, p.greeting())
		return
	}

	watermark := p.maxActionID(ctx)
	// Keep the "typing…" indicator alive while the LLM thinks (Telegram clears it after ~5s).
	askCtx, stopTyping := context.WithCancel(ctx)
	go func() {
		t := time.NewTicker(4 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				_ = p.api.sendChatAction(askCtx, chatID, "typing")
			case <-askCtx.Done():
				return
			}
		}
	}()
	// Shared server-side history: the SAME conversation the web chat uses, so a thread started
	// in the web UI continues here (and vice versa). RAM buffers are gone.
	hist := p.storeHistory()
	reply, err := p.agent.Ask(ctx, text, hist)
	stopTyping()
	if err != nil {
		p.handleAskError(ctx, chatID, err)
		return
	}
	_ = p.st.AppendChatTurn(ctx, text, reply.Reply)
	p.reply(ctx, chatID, reply.Reply)
	p.announcePending(ctx, chatID, watermark)
}

// handleAskError turns an agent failure into a short chat message (rate-limited for the
// not-configured case so a curious chat doesn't spam itself every message).
func (p *poller) handleAskError(ctx context.Context, chatID string, err error) {
	if errors.Is(err, ai.ErrNotConfigured) {
		p.mu.Lock()
		nag := time.Since(p.notCfgAt) >= notConfiguredCD
		if nag {
			p.notCfgAt = time.Now()
		}
		p.mu.Unlock()
		if nag {
			p.reply(ctx, chatID, p.loc("AI не настроен: добавь провайдера в Settings → AI.",
				"AI is not configured: add a provider in Settings → AI."))
		}
		return
	}
	logging.LDD(p.logger, 10, "tgchat", "ASK_FAIL", err.Error())
	p.reply(ctx, chatID, p.loc("Ошибка агента: ", "Agent error: ")+truncate(err.Error(), 300))
}

// announcePending reports pending actions created during the turn (id > watermark) as ✅/❌ buttons.
// Sorted ascending so the oldest proposal arrives first.
func (p *poller) announcePending(ctx context.Context, chatID string, watermark int64) {
	actions, err := p.st.ListAIActions(ctx, "pending")
	if err != nil {
		return
	}
	ids := make([]int64, 0, len(actions))
	for _, a := range actions {
		if a.ID > watermark {
			ids = append(ids, a.ID)
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		act, err := p.st.GetAIAction(ctx, id)
		if err != nil || act.Status != "pending" {
			continue
		}
		vmName := strconv.FormatInt(act.VMID, 10)
		if v, verr := p.st.GetVM(ctx, act.VMID); verr == nil {
			vmName = v.Name
		}
		text := p.loc("Требует подтверждения (vm ", "Needs approval (vm ") + vmName +
			", action #" + strconv.FormatInt(act.ID, 10) + "):\n$ " + act.Command +
			p.loc("\nКоманда НЕ выполнена — нажми кнопку.", "\nThe command is NOT running — press a button.")
		if act.Reason != "" {
			text += "\n" + p.loc("мотив: ", "reason: ") + truncate(act.Reason, 200)
		}
		kb := approveKeyboard(act.ID)
		if _, err := p.api.sendMessage(ctx, chatID, text, kb); err != nil {
			logging.LDD(p.logger, 8, "tgchat", "ANNOUNCE_FAIL", err.Error())
		} else {
			logging.LDD(p.logger, 8, "tgchat", "ANNOUNCED", "action="+strconv.FormatInt(act.ID, 10)+" chat="+chatID)
		}
	}
}

// approveKeyboard builds the ✅/❌ inline pair for one action id.
func approveKeyboard(actionID int64) *inlineKeyboard {
	id := strconv.FormatInt(actionID, 10)
	kb := &inlineKeyboard{}
	kb.Inline = append(kb.Inline, []struct {
		Text string `json:"text"`
		Data string `json:"callback_data"`
	}{
		{"✅ " + "approve", "a:" + id + ":ok"},
		{"❌ " + "reject", "a:" + id + ":no"},
	})
	return kb
}

// region FUNC_poller_handleCallback [DOMAIN(9): Security; CONCEPT(8): ApproveButton; TECH(7): Approver]
// @purpose Resolve a ✅/❌ press: acknowledge instantly, gate on allowlist + still-pending, then
//
//	execute via the SHARED approve-path (telegram) or reject, editing the message in place.
//
// @complexity 6
// endregion FUNC_poller_handleCallback
func (p *poller) handleCallback(ctx context.Context, cb *tgCallback) {
	// Acknowledge first so the client spinner stops regardless of the outcome.
	defer func() { _ = p.api.answerCallbackQuery(ctx, cb.ID, "") }()

	id, verdict, ok := parseCallback(cb.Data)
	if !ok {
		return
	}
	chatID := ""
	msgID := int64(0)
	if cb.Message != nil {
		chatID = strconv.FormatInt(cb.Message.Chat.ID, 10)
		msgID = cb.Message.MessageID
	}
	if chatID == "" || !p.allowed[chatID] {
		logging.LDD(p.logger, 9, "tgchat", "CALLBACK_DENIED", "chat_id="+chatID)
		return
	}

	act, err := p.st.GetAIAction(ctx, id)
	if err != nil {
		_ = p.api.answerCallbackQuery(ctx, cb.ID, p.loc("действие не найдено", "action not found"))
		return
	}
	if act.Status != "pending" {
		_ = p.api.answerCallbackQuery(ctx, cb.ID, p.loc("уже обработано", "already handled"))
		p.editResolved(ctx, chatID, msgID, act.ID, act.Status, act.Output)
		return
	}

	switch verdict {
	case "ok":
		status, out, aerr := p.approver.ApproveAIAction(ctx, id, "telegram")
		if aerr != nil {
			_ = p.api.answerCallbackQuery(ctx, cb.ID, truncate(aerr.Error(), 180))
			return
		}
		p.editResolved(ctx, chatID, msgID, id, status, out)
	case "no":
		_ = p.st.SetAIActionStatus(ctx, id, "rejected", "")
		logging.LDD(p.logger, 8, "tgchat", "REJECTED", "action="+strconv.FormatInt(id, 10)+" chat="+chatID)
		p.editResolved(ctx, chatID, msgID, id, "rejected", "")
	}
}

// editResolved rewrites the announce message with the outcome and no buttons.
func (p *poller) editResolved(ctx context.Context, chatID string, msgID, actionID int64, status, output string) {
	if msgID == 0 {
		return
	}
	mark := map[string]string{"done": "✅", "error": "❌", "rejected": "🚫"}[status]
	if mark == "" {
		mark = "•"
	}
	label := map[string]string{
		"done": p.loc("выполнено", "done"), "error": p.loc("ошибка", "error"),
		"rejected": p.loc("отклонено", "rejected"),
	}[status]
	if label == "" {
		label = status
	}
	text := mark + " action #" + strconv.FormatInt(actionID, 10) + " — " + label
	if output != "" && status != "rejected" {
		text += "\n" + truncate(output, announceTrunc)
	}
	// editMessageText fails for messages older than 48h or already edited — best-effort only.
	if err := p.api.editMessageText(ctx, chatID, msgID, text); err != nil {
		logging.LDD(p.logger, 7, "tgchat", "EDIT_FAIL", err.Error())
	}
}

// parseCallback decodes "a:<id>:ok|no".
func parseCallback(data string) (id int64, verdict string, ok bool) {
	parts := strings.Split(data, ":")
	if len(parts) != 3 || parts[0] != "a" {
		return 0, "", false
	}
	id, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || id <= 0 {
		return 0, "", false
	}
	if parts[2] != "ok" && parts[2] != "no" {
		return 0, "", false
	}
	return id, parts[2], true
}

// maxActionID returns the highest ai_action id (0 on error) — the pre-turn watermark.
func (p *poller) maxActionID(ctx context.Context) int64 {
	actions, err := p.st.ListAIActions(ctx, "")
	if err != nil || len(actions) == 0 {
		return 0
	}
	// ListAIActions is newest-first; the head is the max.
	return actions[0].ID
}

// reply sends text split into Telegram-sized chunks.
func (p *poller) reply(ctx context.Context, chatID, text string) {
	for _, chunk := range splitMessage(text, maxReplyChunk) {
		if _, err := p.api.sendMessage(ctx, chatID, chunk, nil); err != nil {
			logging.LDD(p.logger, 8, "tgchat", "SEND_FAIL", err.Error())
			return
		}
	}
}

// greeting is the /start answer (short — it's a control room, not a marketing bot).
func (p *poller) greeting() string {
	return p.loc(
		"VM Pulse на связи. Спрашивай о серверах и доменах, проси выполнить команды или поставить "+
			"что-то на мониторинг. Опасное требует подтверждения кнопкой.",
		"VM Pulse online. Ask about servers and domains, request commands, or add something to "+
			"monitoring. Anything mutating needs a button confirmation.")
}

// loc picks ru/en by the operator's stored ui_locale (default en).
func (p *poller) loc(ru, en string) string {
	if loc, err := p.st.GetSetting(context.Background(), "ui_locale"); err == nil && loc == "ru" {
		return ru
	}
	return en
}

// storeHistory loads the SHARED conversation (server-side) as agent history.
func (p *poller) storeHistory() []ai.Message {
	msgs, err := p.st.ListChatMessages(context.Background(), 50)
	if err != nil {
		logging.LDD(p.logger, 8, "tgchat", "HISTORY_FAIL", err.Error())
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

// truncate clips s for embedding into chat/audit text.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
