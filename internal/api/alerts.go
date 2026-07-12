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
	"io"
	"net/http"

	"github.com/skibine/vm-pulse/internal/logging"
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
	mux.HandleFunc("DELETE /api/channels/{id}", a.deleteChannel)

	// Fired alerts.
	mux.HandleFunc("GET /api/alerts", a.listAlerts)
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
	writeJSON(w, http.StatusOK, ch)
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
