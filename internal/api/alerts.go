// Package api — alert rules, channels, and fired-alerts endpoints.
//
// region MODULE_CONTRACT [DOMAIN(7): API; CONCEPT(8): Alerting; TECH(8): net/http,go1.22routing]
// @purpose Manage alert rules and delivery channels, attach channels to rules, and list fired
//
//	alerts. TODO(auth): wrap with Plane B session middleware in the auth slice.
//
// @invariants
//   - Newly created rules/channels default to enabled=true when "enabled" is omitted.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: alert-rules, channels, alerts, attach, CRUD, REST
// STRUCTURE: ▶ ┌mux+store┐ → ⊕ registerAlerts → ○ handlers → 〈validate→repo→encode〉 → ⎋ JSON
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/skibine/vm-pulse/internal/alerts"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/monitor"
	"github.com/skibine/vm-pulse/internal/store"
)

// registerAlerts wires all alerting routes onto the mux.
func registerAlerts(mux *http.ServeMux, a *crudAPI) {
	// Alert rules.
	mux.HandleFunc("GET /api/alert-rules", a.listAlertRules)
	mux.HandleFunc("POST /api/alert-rules", a.createAlertRule)
	mux.HandleFunc("DELETE /api/alert-rules/{id}", a.deleteAlertRule)
	mux.HandleFunc("POST /api/alert-rules/{id}/channels", a.attachChannel)
	mux.HandleFunc("GET /api/alert-rules/{id}/channels", a.listRuleChannels)

	// Channels.
	mux.HandleFunc("GET /api/channels", a.listChannels)
	mux.HandleFunc("POST /api/channels", a.createChannel)
	mux.HandleFunc("GET /api/channels/{id}", a.getChannel)
	mux.HandleFunc("PUT /api/channels/{id}", a.updateChannel)
	mux.HandleFunc("DELETE /api/channels/{id}", a.deleteChannel)
	mux.HandleFunc("POST /api/channels/{id}/test", a.testChannel)
	// Resolve a Telegram chat_id from the operator's bot token (auto-capture onboarding aid).
	mux.HandleFunc("POST /api/channels/telegram/resolve", a.resolveTelegramChat)

	// Fired alerts.
	mux.HandleFunc("GET /api/alerts", a.listAlerts)
	mux.HandleFunc("GET /api/alerts/all", a.listAllAlerts)
	mux.HandleFunc("POST /api/alerts/{id}/ack", a.ackAlert)
	mux.HandleFunc("POST /api/alerts/ack-all", a.ackAllAlerts)
	mux.HandleFunc("DELETE /api/alerts", a.clearAllAlerts)

	// Per-VM mute (exclude a VM from fleet-wide rules).
	mux.HandleFunc("GET /api/alert-mutes", a.listAlertMutes)
	mux.HandleFunc("POST /api/vms/{id}/alert-mute", a.setAlertMute)
	// Per-VM alert channels (where a server's alerts are delivered).
	mux.HandleFunc("GET /api/vms/{id}/alert-channels", a.listVMAlertChannels)
	mux.HandleFunc("PUT /api/vms/{id}/alert-channels", a.setVMAlertChannels)
	// Batch: every VM's channel-id set in one response (avoids N+1 fan-out for the fleet/sidebar bells).
	mux.HandleFunc("GET /api/vms/alert-channels", a.listAllVMAlertChannels)
}

// readJSONProbe decodes JSON into dst and also returns a map of present top-level keys,
// so callers can apply "omitted means default" semantics (e.g. enabled=true).
func readJSONProbe(w http.ResponseWriter, r *http.Request, dst any) (map[string]any, bool) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body: " + err.Error()})
		return nil, false
	}
	if err := json.Unmarshal(body, dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return nil, false
	}
	var probe map[string]any
	_ = json.Unmarshal(body, &probe)
	return probe, true
}

// ── Alert rules ─────────────────────────────────────────────────────────────────────

func (a *crudAPI) listAlertRules(w http.ResponseWriter, r *http.Request) {
	rules, err := a.st.ListAlertRules(r.Context())
	if err != nil {
		a.writeErr(w, "listAlertRules", err)
		return
	}
	if rules == nil {
		rules = []store.AlertRule{}
	}
	writeJSON(w, http.StatusOK, rules)
}

func (a *crudAPI) createAlertRule(w http.ResponseWriter, r *http.Request) {
	var rule store.AlertRule
	probe, ok := readJSONProbe(w, r, &rule)
	if !ok {
		return
	}
	if _, set := probe["enabled"]; !set {
		rule.Enabled = true
	}
	id, err := a.st.CreateAlertRule(r.Context(), rule)
	if err != nil {
		a.writeErr(w, "createAlertRule", err)
		return
	}
	a.auditConfig("alert_rule_create", 0, "rule_id="+strconv.FormatInt(id, 10)+" name="+rule.Name)
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (a *crudAPI) deleteAlertRule(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := a.st.DeleteAlertRule(r.Context(), id); err != nil {
		a.writeErr(w, "deleteAlertRule", err)
		return
	}
	a.auditConfig("alert_rule_delete", 0, "rule_id="+strconv.FormatInt(id, 10))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *crudAPI) attachChannel(w http.ResponseWriter, r *http.Request) {
	ruleID, ok := parseID(w, r)
	if !ok {
		return
	}
	var body struct {
		ChannelID int64 `json:"channel_id"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := a.st.AttachChannel(r.Context(), ruleID, body.ChannelID); err != nil {
		a.writeErr(w, "attachChannel", err)
		return
	}
	logging.LDD(a.logger, 7, "attachChannel", "ATTACHED",
		"rule="+itoa64(ruleID)+" channel="+itoa64(body.ChannelID))
	writeJSON(w, http.StatusOK, map[string]string{"status": "attached"})
}

func (a *crudAPI) listRuleChannels(w http.ResponseWriter, r *http.Request) {
	ruleID, ok := parseID(w, r)
	if !ok {
		return
	}
	chs, err := a.st.ListChannelsForRule(r.Context(), ruleID)
	if err != nil {
		a.writeErr(w, "listRuleChannels", err)
		return
	}
	if chs == nil {
		chs = []store.Channel{}
	}
	writeJSON(w, http.StatusOK, chs)
}

// ── Channels ────────────────────────────────────────────────────────────────────────

func (a *crudAPI) listChannels(w http.ResponseWriter, r *http.Request) {
	chs, err := a.st.ListChannels(r.Context())
	if err != nil {
		a.writeErr(w, "listChannels", err)
		return
	}
	if chs == nil {
		chs = []store.Channel{}
	}
	for i := range chs {
		chs[i] = maskChannel(chs[i])
	}
	writeJSON(w, http.StatusOK, chs)
}

func (a *crudAPI) createChannel(w http.ResponseWriter, r *http.Request) {
	var ch store.Channel
	probe, ok := readJSONProbe(w, r, &ch)
	if !ok {
		return
	}
	if _, set := probe["enabled"]; !set {
		ch.Enabled = true
	}
	if msg := validateChannelConfig(ch.Type, ch.Config); msg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
		return
	}
	id, err := a.st.CreateChannel(r.Context(), ch)
	if err != nil {
		a.writeErr(w, "createChannel", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (a *crudAPI) getChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	ch, err := a.st.GetChannel(r.Context(), id)
	if err != nil {
		a.writeErr(w, "getChannel", err)
		return
	}
	writeJSON(w, http.StatusOK, maskChannel(ch))
}

// updateChannel edits a channel. Secret fields (bot_token / webhook secret) are PRESERVED when the
// request omits them, so the operator can rename or fix chat_id without re-pasting the token.
func (a *crudAPI) updateChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var body struct {
		Type    string         `json:"type"`
		Name    string         `json:"name"`
		Config  map[string]any `json:"config"`
		Enabled *bool          `json:"enabled"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	cur, err := a.st.GetChannel(r.Context(), id)
	if err != nil {
		a.writeErr(w, "updateChannel", err)
		return
	}
	cfg := body.Config
	if cfg == nil {
		cfg = map[string]any{}
	}
	// Preserve the existing secret if the update didn't supply one.
	mergeSecret := func(key string) {
		if _, has := cfg[key]; !has {
			if v, ok := cur.Config[key]; ok {
				cfg[key] = v
			}
		}
	}
	mergeSecret("bot_token")
	mergeSecret("secret")
	typ := body.Type
	if typ == "" {
		typ = cur.Type
	}
	name := body.Name
	if name == "" {
		name = cur.Name
	}
	enabled := cur.Enabled
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	if msg := validateChannelConfig(typ, cfg); msg != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": msg})
		return
	}
	if err := a.st.UpdateChannel(r.Context(), store.Channel{ID: id, Type: typ, Name: name, Config: cfg, Enabled: enabled}); err != nil {
		a.writeErr(w, "updateChannel", err)
		return
	}
	updated, _ := a.st.GetChannel(r.Context(), id)
	writeJSON(w, http.StatusOK, maskChannel(updated))
}

func (a *crudAPI) deleteChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := a.st.DeleteChannel(r.Context(), id); err != nil {
		a.writeErr(w, "deleteChannel", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// maskChannel strips secrets from a channel's config before returning it over the API. The stored
// row (read by the evaluator/deliverer) keeps the real secret; only API responses are masked.
// BUG_FIX_CONTEXT: GET /api/channels used to return bot_token / webhook secret in plaintext — a
// secret leak to anyone with a session. Keep the non-secret fields (chat_id, url) for display.
func maskChannel(c store.Channel) store.Channel {
	cfg := map[string]any{}
	for k, v := range c.Config {
		cfg[k] = v
	}
	switch c.Type {
	case "telegram":
		if t, ok := cfg["bot_token"].(string); ok {
			cfg["has_token"] = t != ""
			delete(cfg, "bot_token")
		}
	case "webhook":
		delete(cfg, "secret")
	}
	c.Config = cfg
	return c
}

// testChannel sends a real test message through the channel and returns ok / the delivery error,
// so the operator can verify their bot_token + chat_id without waiting for a real alert.
func (a *crudAPI) testChannel(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	ch, err := a.st.GetChannel(r.Context(), id)
	if err != nil {
		a.writeErr(w, "testChannel", err)
		return
	}
	if !ch.Enabled {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "channel is disabled"})
		return
	}
	// in-app has no external transport to POST — a "test" is a notification row in the bell center.
	// It verifies the only thing that can fail for this channel type: that notifications land.
	if ch.Type == "in-app" {
		_, derr := a.st.CreateNotification(r.Context(), store.Notification{
			Title: "✅ VM Pulse: channel test", Body: "If you see this, the in-app channel is working.",
			Kind: "test",
		})
		if derr != nil {
			logging.LDD(a.logger, 8, "testChannel", "INAPP_FAIL", derr.Error())
			writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": derr.Error()})
			return
		}
		logging.LDD(a.logger, 8, "testChannel", "INAPP_OK", fmt.Sprintf("channel=%d", id))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
		return
	}
	reg := alerts.DefaultRegistry(a.logger)
	impl, found := reg.Get(ch.Type)
	if !found {
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": "unknown channel type: " + ch.Type})
		return
	}
	msg := alerts.Message{
		Severity: "warning", RuleName: "test", Title: "✅ VM Pulse: channel test",
		Body: "If you see this, the channel is configured correctly.",
	}
	if derr := impl.Deliver(r.Context(), ch.Config, msg); derr != nil {
		logging.LDD(a.logger, 8, "testChannel", "FAIL", derr.Error())
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": derr.Error()})
		return
	}
	logging.LDD(a.logger, 8, "testChannel", "OK", fmt.Sprintf("channel=%d type=%s", id, ch.Type))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// resolveTelegramChat auto-captures the operator's chat_id by calling getUpdates on their bot token
// once. The token is supplied in the request body (never embedded) and used only for this lookup.
func (a *crudAPI) resolveTelegramChat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		BotToken string `json:"bot_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid body"})
		return
	}
	chatID, err := alerts.ResolveTelegramChatID(r.Context(), body.BotToken, "")
	if err != nil {
		logging.LDD(a.logger, 8, "resolveTelegram", "FAIL", err.Error())
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": err.Error()})
		return
	}
	logging.LDD(a.logger, 8, "resolveTelegram", "OK", "chat_id resolved")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "chat_id": chatID})
}

// ── Alerts ──────────────────────────────────────────────────────────────────────────

func (a *crudAPI) listAlerts(w http.ResponseWriter, r *http.Request) {
	limit := 50
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if n, err := atoiPositive(raw); err == nil {
			limit = n
		}
	}
	alerts, err := a.st.ListAlerts(r.Context(), limit)
	if err != nil {
		a.writeErr(w, "listAlerts", err)
		return
	}
	if alerts == nil {
		alerts = []store.Alert{}
	}
	writeJSON(w, http.StatusOK, alerts)
}

// region FUNC_listAllAlerts [DOMAIN(7): API; CONCEPT(7): ReadHistory; TECH(6): net/http]
// @purpose Paged + filtered fired-alert history for the bell modal ("show all"): ?page,
//
//	?page_size (max 200), ?severity (warning|critical), ?vm_id, ?from/?to (YYYY-MM-DD).
//	Returns {alerts,total,page,page_size}. (Plain GET /api/alerts keeps its legacy array shape.)
//
// @complexity 4
// endregion FUNC_listAllAlerts
func (a *crudAPI) listAllAlerts(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := max(1, atoiDefault(q.Get("page"), 1))
	size := clampInt(atoiDefault(q.Get("page_size"), 50), 1, 200)
	var vmID *int64
	if raw := q.Get("vm_id"); raw != "" {
		if n, err := strconv.ParseInt(raw, 10, 64); err == nil && n > 0 {
			vmID = &n
		}
	}
	alerts, total, err := a.st.ListAlertsFiltered(r.Context(), store.AlertFilter{
		Severity: q.Get("severity"), VMID: vmID, From: q.Get("from"), To: q.Get("to"),
		UnackOnly: q.Get("unack") == "1",
		Limit:     size, Offset: (page - 1) * size,
	})
	if err != nil {
		a.writeErr(w, "listAllAlerts", err)
		return
	}
	if alerts == nil {
		alerts = []store.Alert{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"alerts": alerts, "total": total, "page": page, "page_size": size,
	})
}

// int64s maps []int64 to []string (audit detail helper).
func int64s(xs []int64) []string {
	out := make([]string, 0, len(xs))
	for _, x := range xs {
		out = append(out, strconv.FormatInt(x, 10))
	}
	return out
}

// region FUNC_ackAlert [DOMAIN(7): API; CONCEPT(6): Acknowledge; TECH(5): net/http]
// @purpose Mark one fired alert acknowledged (the "read" click of the alerts tab).
// @complexity 2
// endregion FUNC_ackAlert
func (a *crudAPI) ackAlert(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	if err := a.st.AcknowledgeAlert(r.Context(), id); err != nil {
		a.writeErr(w, "ackAlert", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

// region FUNC_ackAllAlerts [DOMAIN(7): API; CONCEPT(6): Acknowledge; TECH(4): net/http]
// @purpose Acknowledge all unacknowledged alerts ("mark all read" of the alerts tab).
// @complexity 2
// endregion FUNC_ackAllAlerts
func (a *crudAPI) ackAllAlerts(w http.ResponseWriter, r *http.Request) {
	if err := a.st.AcknowledgeAllAlerts(r.Context()); err != nil {
		a.writeErr(w, "ackAllAlerts", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
}

// region FUNC_clearAllAlerts [DOMAIN(7): API; CONCEPT(6): Purge; TECH(5): net/http]
// @purpose DELETE /api/alerts?before=YYYY-MM-DD (empty = all) — the modal's clear buttons.
// @complexity 3
// endregion FUNC_clearAllAlerts
func (a *crudAPI) clearAllAlerts(w http.ResponseWriter, r *http.Request) {
	deleted, err := a.st.DeleteAlerts(r.Context(), r.URL.Query().Get("before"))
	if err != nil {
		a.writeErr(w, "clearAllAlerts", err)
		return
	}
	logging.LDD(a.logger, 8, "clearAllAlerts", "CLEARED", fmt.Sprintf("rows=%d", deleted))
	writeJSON(w, http.StatusOK, map[string]any{"status": "cleared", "deleted": deleted})
}

// listAlertMutes returns the VM ids excluded from fleet-wide rules.
func (a *crudAPI) listAlertMutes(w http.ResponseWriter, r *http.Request) {
	ids, err := a.st.MutedVMIDs(r.Context())
	if err != nil {
		a.writeErr(w, "listAlertMutes", err)
		return
	}
	out := make([]int64, 0, len(ids))
	for id := range ids {
		out = append(out, id)
	}
	writeJSON(w, http.StatusOK, map[string]any{"vm_ids": out})
}

// setAlertMute mutes/unmutes a VM for fleet-wide rules (the "all except this one" flow).
func (a *crudAPI) setAlertMute(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var body struct {
		On bool `json:"on"`
	}
	_, _ = readJSONProbe(w, r, &body)
	if err := a.st.SetAlertMute(r.Context(), id, body.On); err != nil {
		a.writeErr(w, "setAlertMute", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "muted": body.On})
}

// listVMAlertChannels returns the delivery channels attached to a server's liveness alert.
func (a *crudAPI) listVMAlertChannels(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	chs, err := a.st.ListVMChannels(r.Context(), id)
	if err != nil {
		a.writeErr(w, "listVMAlertChannels", err)
		return
	}
	if chs == nil {
		chs = []store.Channel{}
	}
	for i := range chs {
		chs[i] = maskChannel(chs[i])
	}
	writeJSON(w, http.StatusOK, chs)
}

// setVMAlertChannels replaces a server's alert channels (the picker sends the full set).
func (a *crudAPI) setVMAlertChannels(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var body struct {
		ChannelIDs []int64 `json:"channel_ids"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := a.st.SetVMChannels(r.Context(), id, body.ChannelIDs); err != nil {
		a.writeErr(w, "setVMAlertChannels", err)
		return
	}
	a.auditConfig("vm_channels_set", id,
		"vm="+strconv.FormatInt(id, 10)+" channels="+strings.Join(int64s(body.ChannelIDs), ","))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// listAllVMAlertChannels returns { "<vm_id>": [channel_id,...] } for every server in one shot, so the
// fleet matrix and sidebar render all bells from a single request instead of N per-VM calls.
func (a *crudAPI) listAllVMAlertChannels(w http.ResponseWriter, r *http.Request) {
	m, err := a.st.ListAllVMChannelIDs(r.Context())
	if err != nil {
		a.writeErr(w, "listAllVMAlertChannels", err)
		return
	}
	// JSON object keys are strings; marshal int64 vm ids as string keys (the frontend reads them back).
	out := map[string][]int64{}
	for vmID, ids := range m {
		out[itoa64(vmID)] = ids
	}
	writeJSON(w, http.StatusOK, out)
}

func itoa64(n int64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = digits[n%10]
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

func atoiPositive(s string) (int, error) {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errInvalidInt
		}
		n = n*10 + int(c-'0')
	}
	if n <= 0 {
		return 0, errInvalidInt
	}
	return n, nil
}

var errInvalidInt = &apiErr{"invalid integer"}

type apiErr struct{ msg string }

func (e *apiErr) Error() string { return e.msg }

// validateChannelConfig guards channel egress against SSRF + bot-token exfiltration. Telegram
// api_url may only be the official host (the override exists for tests; pointing it elsewhere would
// POST the bot token into that host's path). Webhook URLs must be https and must not target
// loopback/private/link-local/cloud-metadata addresses. Returns "" when valid.
func validateChannelConfig(chType string, config map[string]any) string {
	switch chType {
	case "telegram":
		if raw, _ := config["api_url"].(string); raw != "" {
			// BUG_FIX_CONTEXT (audit round 2): a prefix check let https://api.telegram.org.evil.com
			// through - the bot token would then be POSTed to the attacker's host. Parse and
			// compare the FULL host.
			u, perr := url.Parse(raw)
			if perr != nil || u.Scheme != "https" || u.Hostname() != "api.telegram.org" {
				return "telegram api_url may only be https://api.telegram.org (pointing it elsewhere leaks the bot token)"
			}
		}
	case "webhook":
		raw, _ := config["url"].(string)
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "https" {
			return "webhook url must be https"
		}
		if isPrivateOrLoopbackHost(u.Hostname()) {
			return "webhook url must not target a loopback/private/cloud-metadata address"
		}
		// BUG_FIX_CONTEXT: the literal check above is blind to hostnames that RESOLVE to
		// private/metadata ranges (10.0.0.1.nip.io, DNS rebinding) - resolve and verify.
		if monitor.HostBlocked(u.Hostname()) {
			return "webhook url resolves to a blocked (private/metadata) address"
		}
		if ips, err := net.LookupIP(u.Hostname()); err == nil {
			for _, ip := range ips {
				if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
					return "webhook url resolves to a loopback/private address"
				}
			}
		}
	}
	return ""
}

// isPrivateOrLoopbackHost blocks the classic SSRF/cloud-metadata targets without DNS resolution.
func isPrivateOrLoopbackHost(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || host == "localhost" || host == "metadata" || host == "metadata.google.internal" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
	}
	// Bare hostnames that look like private ranges (e.g. "10.0.0.1.nip.io" won't parse as IP but the
	// common literal forms above are the real metadata targets).
	return false
}
