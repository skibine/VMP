// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): AlertAPI; TECH(8): go test,httptest]
// @purpose Verify REST for alert rules/channels/attach and fired-alert listing.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, alert-rules, channels, attach, alerts, HTTP
// STRUCTURE: ▶ ┌server┐ → POST rule+channel → ○ attach → ⚡ insert alert → GET /api/alerts → assert
package api

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"github.com/skibine/vm-pulse/internal/store"
)

func TestHTTP_AlertRulesChannelsAttach(t *testing.T) {
	srv, buf := newServer(t)

	// Create rule (enabled defaults to true when omitted).
	rec := do(srv, http.MethodPost, "/api/alert-rules",
		`{"name":"down","trigger_status":"critical","severity":"critical","cooldown_sec":60}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create rule want 201, got %d: %s", rec.Code, rec.Body.String())
	}
	var rule struct {
		ID int64 `json:"id"`
	}
	decode(t, rec, &rule)

	// Validation -> 400.
	rec = do(srv, http.MethodPost, "/api/alert-rules", `{"name":"","trigger_status":"critical","severity":"critical"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("validation want 400, got %d", rec.Code)
	}

	// Create channel.
	rec = do(srv, http.MethodPost, "/api/channels", `{"type":"log","name":"default"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create channel want 201, got %d", rec.Code)
	}
	var ch struct {
		ID int64 `json:"id"`
	}
	decode(t, rec, &ch)

	// Attach.
	rec = do(srv, http.MethodPost, "/api/alert-rules/"+strconv.FormatInt(rule.ID, 10)+"/channels",
		`{"channel_id":`+strconv.FormatInt(ch.ID, 10)+`}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("attach want 200, got %d", rec.Code)
	}

	// List channels for rule.
	rec = do(srv, http.MethodGet, "/api/alert-rules/"+strconv.FormatInt(rule.ID, 10)+"/channels", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("rule channels want 200, got %d", rec.Code)
	}
	var list []map[string]any
	decode(t, rec, &list)
	if len(list) != 1 {
		t.Fatalf("rule channels want 1, got %d", len(list))
	}

	// Unknown rule delete -> 404.
	rec = do(srv, http.MethodDelete, "/api/alert-rules/9999", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("delete unknown rule want 404, got %d", rec.Code)
	}

	printIMPFromBuf(t, buf)
	assertContains(t, buf, "[IMP:7][attachChannel][ATTACHED]")
}

func TestHTTP_AlertsList(t *testing.T) {
	srv, _ := newServer(t)
	ctx := context.Background()
	rid, _ := srv.store.CreateAlertRule(ctx, store.AlertRule{
		Name: "r", TriggerStatus: "critical", Severity: "critical", CooldownSec: 60, Enabled: true,
	})
	_, _ = srv.store.InsertAlert(ctx, store.Alert{
		RuleID: rid, CheckID: 1, Severity: "critical", Message: "down",
		DeliveryLog: map[string]any{"1": map[string]any{"ok": true}},
	})

	rec := do(srv, http.MethodGet, "/api/alerts", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("list alerts want 200, got %d", rec.Code)
	}
	var arr []map[string]any
	decode(t, rec, &arr)
	if len(arr) != 1 {
		t.Fatalf("alerts want 1, got %d", len(arr))
	}
	if arr[0]["severity"] != "critical" {
		t.Fatalf("alert severity want critical, got %v", arr[0]["severity"])
	}
}
