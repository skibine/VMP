// Package alerts — generic HTTP webhook delivery channel.
//
// region MODULE_CONTRACT [DOMAIN(7): Alerting; CONCEPT(7): Webhook; TECH(8): net/http]
// @purpose Deliver alerts as a JSON POST to any HTTP receiver so one implementation covers Slack,
//
//	Discord, Gotify, ntfy, Home Assistant and custom scripts (the receiver adapts the envelope).
//	An optional shared secret signs the body with HMAC-SHA256 so the receiver can verify the sender.
//
// @invariants
//   - Missing url -> error (recorded in delivery_log), never a panic.
//   - Delivery is best-effort with a timeout; HTTP non-2xx -> error.
//   - Plane A: uses only the channel secret, never VM SSH credentials.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: webhook, channel, http, json, hmac, signature, slack, discord, gotify, ntfy
// STRUCTURE: ▶ ┌url+secret?┐ → ⊕ JSON envelope → ⚡ POST → [HMAC sig] → 〈2xx?〉 → ⎷ err|nil
package alerts

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/skibine/vmp/internal/monitor"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// region STRUCT_WebhookChannel [DOMAIN(7): Alerting; CONCEPT(6): Plugin; TECH(8): net/http]
// @purpose Generic HTTP webhook delivery (signed JSON POST).
// endregion STRUCT_WebhookChannel
type WebhookChannel struct{}

func (*WebhookChannel) Type() string { return "webhook" }

// region FUNC_WebhookChannel_Deliver [DOMAIN(7): Alerting; CONCEPT(7): Deliver; TECH(8): net/http]
// @purpose POST a JSON alert envelope to config["url"]; if config["secret"] is set, add an
//
//	X-VMPulse-Signature header (sha256=<hex>) over the body for sender verification.
//
// @complexity 5
// endregion FUNC_WebhookChannel_Deliver
func (*WebhookChannel) Deliver(ctx context.Context, config map[string]any, msg Message) error {
	target := strings.TrimSpace(strConfig(config, "url"))
	if target == "" {
		return fmt.Errorf("webhook: url required")
	}

	payload := map[string]any{
		"source":     "vmpulse",
		"severity":   msg.Severity,
		"title":      msg.Title,
		"body":       msg.Body,
		"rule":       msg.RuleName,
		"check_type": msg.CheckType,
		"check_id":   msg.CheckID,
		"fired_at":   time.Now().UTC().Format(time.RFC3339),
	}
	if msg.VMID != nil {
		payload["vm_id"] = *msg.VMID
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook: marshal: %w", err)
	}

	// BUG_FIX_CONTEXT (audit round 2): the URL was validated at channel-config time only;
	// DNS rebinding between create and delivery (TOCTOU) could retarget the POST at
	// internal hosts. Re-check the host at delivery before dialing.
	if u, uerr := url.Parse(target); uerr == nil {
		if monitor.HostBlocked(u.Hostname()) {
			return fmt.Errorf("webhook: host resolves to a blocked address (re-check failed)")
		}
	}
	client := monitor.SafeClient(10 * time.Second)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("webhook: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Optional HMAC-SHA256 signing so a receiver can prove the request came from VM Pulse.
	if secret := strConfig(config, "secret"); secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(body)
		req.Header.Set("X-VMPulse-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook: request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook: status %d: %s", resp.StatusCode, string(b))
	}
	return nil
}
