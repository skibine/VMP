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
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const defaultTelegramAPI = "https://api.telegram.org"

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
		return fmt.Errorf("telegram: request: %w", err)
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
