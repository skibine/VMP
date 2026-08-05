// Package alerts — Telegram delivery channel.
//
// region MODULE_CONTRACT [DOMAIN(7): Alerting; CONCEPT(7): Telegram; TECH(8): net/http]
// @purpose Deliver alerts via the Telegram Bot API (sendMessage). api_url is overridable in
//
//	config so tests can point at an httptest server.
//
// @invariants
//   - Missing bot_token/chat_id -> error (recorded in delivery_log), never a panic.
//   - Delivery is best-effort with a timeout; HTTP non-2xx -> error.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: telegram, channel, bot api, sendMessage, chat_id, bot_token, delivery
// STRUCTURE: ▶ ┌config┐ → ○ token+chat+api_url → ⚡ POST sendMessage → 〈2xx?〉 → ⎷ err|nil
package alerts

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const defaultTelegramAPI = "https://api.telegram.org"

// reBotToken matches a Telegram bot token as it appears in an API path (/bot<digits>:<alnum>/...).
// Used to scrub tokens out of error strings before they reach API responses or logs.
var reBotToken = regexp.MustCompile(`bot\d+:[A-Za-z0-9_-]+`)

// redactToken replaces any embedded bot token in s with "bot***" so transport errors (which include
// the full /bot<TOKEN>/... URL) never leak the secret to the client or into logs.
func redactToken(s string) string { return reBotToken.ReplaceAllString(s, "bot***") }

// region STRUCT_TelegramChannel [DOMAIN(7): Alerting; CONCEPT(6): Plugin; TECH(8): net/http]
// @purpose Telegram Bot API delivery.
// endregion STRUCT_TelegramChannel
type TelegramChannel struct{}

func (*TelegramChannel) Type() string { return "telegram" }

// region FUNC_TelegramChannel_Deliver [DOMAIN(7): Alerting; CONCEPT(7): Deliver; TECH(8): net/http]
// @purpose POST a sendMessage request to the Telegram Bot API.
// @complexity 5
// endregion FUNC_TelegramChannel_Deliver
func (*TelegramChannel) Deliver(ctx context.Context, config map[string]any, msg Message) error {
	token := strConfig(config, "bot_token")
	chatID := strConfig(config, "chat_id")
	if token == "" || chatID == "" {
		return fmt.Errorf("telegram: bot_token and chat_id required")
	}
	apiBase := strConfig(config, "api_url")
	if apiBase == "" {
		apiBase = defaultTelegramAPI
	}
	endpoint := strings.TrimRight(apiBase, "/") + "/bot" + token + "/sendMessage"

	form := url.Values{}
	form.Set("chat_id", chatID)
	form.Set("text", renderText(msg))
	if msg.Severity == "critical" {
		form.Set("disable_notification", "false")
	}

	timeout := 10 * time.Second
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return fmt.Errorf("telegram: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		// net/http wraps transport failures in *url.Error whose string includes the full request URL,
		// i.e. /bot<TOKEN>/sendMessage. Never surface that: redact the token before returning/logging.
		return fmt.Errorf("telegram: request failed: %s", redactToken(err.Error()))
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("telegram: api status %d: %s", resp.StatusCode, string(body))
	}
	return nil
}

// strConfig reads a string config field (accepts string/number).
func strConfig(config map[string]any, key string) string {
	if config == nil {
		return ""
	}
	switch x := config[key].(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%v", x)
	}
	return ""
}

// renderText builds the Telegram message body.
func renderText(msg Message) string {
	sev := strings.ToUpper(msg.Severity)
	if sev == "" {
		sev = "ALERT"
	}
	vm := ""
	if msg.VMID != nil {
		vm = fmt.Sprintf(" vm=%d", *msg.VMID)
	}
	return fmt.Sprintf("VM Pulse %s: %s%s\n%s\n(rule=%s check=%s/%d)",
		sev, msg.Title, vm, msg.Body, msg.RuleName, msg.CheckType, msg.CheckID)
}

// region FUNC_ResolveTelegramChatID [DOMAIN(7): Alerting; CONCEPT(8): Onboarding; TECH(7): net/http,json]
// @purpose Enable zero-friction Telegram setup: after the operator pastes a bot token, call the
// @purpose bot's getUpdates ONCE and return the most recent chat_id seen, so they never have to
// @purpose hunt for their numeric id manually. No token is ever embedded in the binary — the token
// @purpose is supplied per-request by the operator and used only for this transient lookup.
// @uses Telegram Bot API getUpdates (offset=-1 -> last update only, does not confirm prior updates)
// @io token, apiBase -> (chatID string, error)
// @complexity 4
// endregion FUNC_ResolveTelegramChatID
func ResolveTelegramChatID(ctx context.Context, token, apiBase string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("telegram: bot_token required")
	}
	if apiBase == "" {
		apiBase = defaultTelegramAPI
	}
	// offset=-1 returns only the last update without confirming/deleting earlier ones, so this does
	// not interfere if the operator ever polls the same bot themselves.
	endpoint := strings.TrimRight(apiBase, "/") + "/bot" + token + "/getUpdates?offset=-1&limit=1&timeout=0"
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("telegram resolve: build: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		// Transport error stringifies the URL (which embeds the token) — redact before returning.
		return "", fmt.Errorf("telegram resolve: request failed: %s", redactToken(err.Error()))
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("telegram resolve: api status %d: %s", resp.StatusCode, string(body))
	}
	var parsed struct {
		OK     bool `json:"ok"`
		Result []struct {
			Message       *tgChat `json:"message"`
			EditedMessage *tgChat `json:"edited_message"`
			ChannelPost   *tgChat `json:"channel_post"`
		} `json:"result"`
		Description string `json:"description"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("telegram resolve: parse: %w", err)
	}
	if !parsed.OK {
		return "", fmt.Errorf("telegram resolve: %s", parsed.Description)
	}
	for i := len(parsed.Result) - 1; i >= 0; i-- {
		u := parsed.Result[i]
		if u.Message != nil && u.Message.Chat != nil && u.Message.Chat.ID != 0 {
			return strconv.FormatInt(u.Message.Chat.ID, 10), nil
		}
		if u.EditedMessage != nil && u.EditedMessage.Chat != nil && u.EditedMessage.Chat.ID != 0 {
			return strconv.FormatInt(u.EditedMessage.Chat.ID, 10), nil
		}
		if u.ChannelPost != nil && u.ChannelPost.Chat != nil && u.ChannelPost.Chat.ID != 0 {
			return strconv.FormatInt(u.ChannelPost.Chat.ID, 10), nil
		}
	}
	return "", fmt.Errorf("telegram resolve: no messages yet — send any message to your bot, then retry")
}

type tgChat struct {
	Chat *struct {
		ID int64 `json:"id"`
	} `json:"chat"`
}
