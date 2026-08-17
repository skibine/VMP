// Package tgchat — Telegram bridge: chat frontend for the AI agent.
//
// The bridge is a TRANSPORT, not a second agent: it long-polls the Bot API, feeds each operator
// message into the SAME ai.Agent the web chat uses, and returns the reply to the chat. Pending
// command proposals surface as inline ✅/❌ buttons; the callback executes through the same
// approve-path as the web UI (audit-logged, destructive-pattern backstop intact).
//
// region MODULE_CONTRACT [DOMAIN(8): AI,Integration; CONCEPT(8): TelegramChat; TECH(8): net/http,long-poll]
// @purpose Let the operator talk to the VM Pulse AI agent from Telegram when the web UI is not at
//
//	hand — same tools, same answers, plus mobile approve buttons for proposed commands.
//
// @invariants
//   - Only messages from the channel's own chat_id are processed; anything else is audited and ignored.
//   - The agent_chat_enabled flag is per-channel and OFF by default (explicit operator opt-in).
//   - No credentials/vault/2FA operation is ever performed through this bridge.
//   - All Bot API errors are token-redacted before they reach logs.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: telegram, chat, bridge, bot api, getUpdates, long-poll, callback, approve, ai agent
// STRUCTURE: ▶ Manager: ○ ListChannels (30s) → ⊕ pollers keyed by bot_token → ⎋ ; Poller: ⚡ getUpdates(25s) → ◇ allowed? → ⚡ Ask → ⊕ split reply → ⚡ sendMessage ; ⚡ callback → Approver ✅/❌
package tgchat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultBotAPIBase = "https://api.telegram.org"

// tgUpdate is one Bot API update (a message or a button callback).
type tgUpdate struct {
	UpdateID      int64      `json:"update_id"`
	Message       *tgMessage `json:"message"`
	CallbackQuery *tgCallback `json:"callback_query"`
}

// tgMessage is a chat message (only Text is handled; stickers/photos are ignored).
type tgMessage struct {
	MessageID int64    `json:"message_id"`
	Chat      tgChatRef `json:"chat"`
	Text      string   `json:"text"`
}

// tgChatRef identifies the chat a message belongs to.
type tgChatRef struct {
	ID int64 `json:"id"`
}

// tgCallback is an inline-button press.
type tgCallback struct {
	ID      string     `json:"id"`
	Data    string     `json:"data"`
	Message *tgMessage `json:"message"`
}

// inlineKeyboard is the ✅/❌ markup sent with a pending-action announcement.
type inlineKeyboard struct {
	Inline [][]struct {
		Text string `json:"text"`
		Data string `json:"callback_data"`
	} `json:"inline_keyboard"`
}

// region STRUCT_botAPI [DOMAIN(7): Integration; CONCEPT(7): BotClient; TECH(8): net/http]
// @purpose Minimal Bot API client: getUpdates / sendMessage / editMessageText / answerCallbackQuery /
//
//	sendChatAction. apiBase is overridable (tests point it at an httptest server).
//
// @invariants
//   - Every error string passes through redactToken (transport errors embed the bot token in the URL).
//   - The HTTP client timeout exceeds the long-poll timeout (35s vs 25s) so long polls are not cut.
//
// endregion STRUCT_botAPI
type botAPI struct {
	token   string
	apiBase string
	client  *http.Client
}

func newBotAPI(token, apiBase string) *botAPI {
	if apiBase == "" {
		apiBase = defaultBotAPIBase
	}
	return &botAPI{token: token, apiBase: apiBase, client: &http.Client{Timeout: 35 * time.Second}}
}

// errBotConflict marks a 409 from the Bot API (another poller/webhook owns the update queue).
type errBotConflict struct{ detail string }

func (e *errBotConflict) Error() string {
	return "telegram 409 conflict: " + e.detail
}

// IsBotConflict reports whether err is the 409-another-poller case.
func IsBotConflict(err error) bool {
	var c *errBotConflict
	return errors.As(err, &c)
}

// region FUNC_botAPI_call [DOMAIN(7): Integration; CONCEPT(7): HTTP; TECH(7): net/http]
// @purpose One authenticated Bot API call: GET (params) or POST (form-encoded); shared response
//
//	parsing with token redaction and 409 detection.
//
// @complexity 5
// endregion FUNC_botAPI_call
func (b *botAPI) call(ctx context.Context, method string, params url.Values, out any) error {
	if params == nil {
		params = url.Values{}
	}
	endpoint := strings.TrimRight(b.apiBase, "/") + "/bot" + b.token + "/" + method
	var req *http.Request
	var err error
	if method == "getUpdates" {
		endpoint += "?" + params.Encode()
		req, err = http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	} else {
		req, err = http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(params.Encode()))
	}
	if err != nil {
		return fmt.Errorf("telegram %s: build: %w", method, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := b.client.Do(req)
	if err != nil {
		// url.Error stringifies the full URL (which embeds the token) — redact before surfacing.
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return fmt.Errorf("telegram %s: request failed: %s", method, redactToken(err.Error()))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusConflict {
		return &errBotConflict{detail: redactToken(string(body))}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("telegram %s: api status %d: %s", method, resp.StatusCode, redactToken(string(body)))
	}
	if out == nil {
		return nil
	}
	var envelope struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
		Result      json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return fmt.Errorf("telegram %s: parse: %w", method, err)
	}
	if !envelope.OK {
		return fmt.Errorf("telegram %s: %s", method, redactToken(envelope.Description))
	}
	if len(envelope.Result) == 0 || string(envelope.Result) == "null" {
		return nil
	}
	return json.Unmarshal(envelope.Result, out)
}

// getUpdates long-polls for updates (timeout seconds; client timeout must exceed it).
// offset confirms all earlier updates and fetches from there.
func (b *botAPI) getUpdates(ctx context.Context, offset int64, timeout int) ([]tgUpdate, error) {
	var out []tgUpdate
	err := b.call(ctx, "getUpdates", url.Values{
		"offset":  {strconv.FormatInt(offset, 10)},
		"timeout": {strconv.Itoa(timeout)},
		"limit":   {"32"},
	}, &out)
	return out, err
}

// sendMessage delivers text (optionally with an inline keyboard) and returns the message id
// (needed later for editMessageText after a button press).
func (b *botAPI) sendMessage(ctx context.Context, chatID, text string, kb *inlineKeyboard) (int64, error) {
	form := url.Values{
		"chat_id": {chatID},
		"text":    {text},
	}
	if kb != nil {
		raw, err := json.Marshal(kb)
		if err != nil {
			return 0, err
		}
		form.Set("reply_markup", string(raw))
	}
	var msg struct {
		MessageID int64 `json:"message_id"`
	}
	if err := b.call(ctx, "sendMessage", form, &msg); err != nil {
		return 0, err
	}
	return msg.MessageID, nil
}

// editMessageText replaces a previously sent message (used to resolve the ✅/❌ buttons in place).
func (b *botAPI) editMessageText(ctx context.Context, chatID string, messageID int64, text string) error {
	return b.call(ctx, "editMessageText", url.Values{
		"chat_id":    {chatID},
		"message_id": {strconv.FormatInt(messageID, 10)},
		"text":       {text},
	}, nil)
}

// answerCallbackQuery acknowledges a button press (stops the client-side spinner).
func (b *botAPI) answerCallbackQuery(ctx context.Context, callbackID, text string) error {
	form := url.Values{"callback_query_id": {callbackID}}
	if text != "" {
		form.Set("text", text)
	}
	return b.call(ctx, "answerCallbackQuery", form, nil)
}

// sendChatAction shows a transient status in the chat ("typing" while the LLM thinks).
func (b *botAPI) sendChatAction(ctx context.Context, chatID, action string) error {
	return b.call(ctx, "sendChatAction", url.Values{
		"chat_id": {chatID},
		"action":  {action},
	}, nil)
}

// redactToken scrubs a bot token out of any error string (mirrors alerts.redactToken; duplicated
// here because the alerts helper is package-private and tgchat must not depend on alerts internals).
var reBotToken = regexp.MustCompile(`bot\d+:[A-Za-z0-9_-]+`)

func redactToken(s string) string { return reBotToken.ReplaceAllString(s, "bot***") }

// splitMessage cuts a long reply into <=limit chunks on line boundaries (Telegram caps at 4096).
func splitMessage(text string, limit int) []string {
	if limit <= 0 {
		limit = 4000
	}
	var out []string
	for len(text) > 0 {
		if len(text) <= limit {
			return append(out, text)
		}
		cut := limit
		if i := strings.LastIndexByte(text[:limit], '\n'); i > limit/2 {
			cut = i + 1
		} else if j := strings.LastIndexByte(text[:limit], ' '); j > limit/2 {
			cut = j + 1
		}
		out = append(out, text[:cut])
		text = text[cut:]
	}
	return out
}
