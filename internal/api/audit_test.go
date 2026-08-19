// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): AuditViewer; TECH(8): go test,httptest]
// @purpose Verify GET /api/audit (filters: category/date/vm/success/q, pagination, total) and
//
//	DELETE /api/audit (all / before-date), plus the invariant that clearing rows does not break
//	VerifyChain for kept rows.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, audit, events, filters, pagination, clear, verify chain
// STRUCTURE: ▶ ┌store+audit rows┐ → ⚡ GET ?category&vm_id&page → 〈total/len?〉 → ⚡ DELETE ?before → ◇ VerifyChain → ⎋
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/skibine/vmp/internal/audit"
	"github.com/skibine/vmp/internal/store"
)

// seedAudit writes a deterministic event set (mix of categories/planes/vms).
func seedAudit(t *testing.T, srv *Server) {
	t.Helper()
	entries := []audit.Entry{
		{Plane: audit.PlaneB, Action: "auth.login", Success: true, Detail: `{"ok":true}`, IPAddress: "10.0.0.9"},
		{Plane: audit.PlaneB, Action: "ai_action_run", Success: true, Detail: "action=1 vm=3 cmd=uptime via=web"},
		{Plane: audit.PlaneB, Action: "ai_action_run", Success: false, Detail: "action=2 vm=12 cmd=ls via=telegram dial_failed=auth"},
		{Plane: audit.PlaneA, Action: "ai_add_domain", TargetType: "domain", TargetID: "5", Success: true},
		{Plane: audit.PlaneB, Action: "ssh_session_open", Success: true, Detail: "vm=3 user=root"},
		{Plane: audit.PlaneB, Action: "tg_chat_denied", Success: false, Detail: "chat_id=999"},
		{Plane: audit.PlaneA, Action: "service.start", Success: true},
	}
	for _, e := range entries {
		if err := audit.Append(srv.store.DB, srv.logger, e); err != nil {
			t.Fatalf("seed %s: %v", e.Action, err)
		}
	}
}

func auditGet(t *testing.T, srv *Server, query string) (events []map[string]any, total float64, page float64) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/audit"+query, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s: %d %s", query, rec.Code, rec.Body.String())
	}
	var body struct {
		Events []map[string]any `json:"events"`
		Total  float64          `json:"total"`
		Page   float64          `json:"page"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return body.Events, body.Total, body.Page
}

func TestAudit_ListFiltersAndPaging(t *testing.T) {
	srv, buf := newServer(t)
	seedAudit(t, srv)

	// All: 7 events, newest first.
	ev, total, _ := auditGet(t, srv, "")
	if total != 7 || len(ev) != 7 {
		t.Fatalf("want 7/7, got %d/%v", len(ev), total)
	}
	if ev[0]["action"] != "service.start" {
		t.Fatalf("newest first violated: %v", ev[0]["action"])
	}
	if ev[0]["category"] != "service" {
		t.Fatalf("category derive failed: %v", ev[0]["category"])
	}

	// Category=ai: ai_action_run x2 + ai_add_domain = 3.
	_, total, _ = auditGet(t, srv, "?category=ai")
	if total != 3 {
		t.Fatalf("category=ai want 3, got %v", total)
	}

	// vm_id=3: matches "vm=3 ..." rows (ai_action_run action=1, ssh_session_open) but NOT vm=12.
	ev, total, _ = auditGet(t, srv, "?vm_id=3")
	if total != 2 {
		t.Fatalf("vm_id=3 want 2, got %v (%v)", total, actions(ev))
	}
	// vm_id=12 matches only its own row.
	_, total, _ = auditGet(t, srv, "?vm_id=12")
	if total != 1 {
		t.Fatalf("vm_id=12 want 1, got %v", total)
	}

	// success=false: dial-failed action + tg_chat_denied = 2.
	_, total, _ = auditGet(t, srv, "?success=false")
	if total != 2 {
		t.Fatalf("success=false want 2, got %v", total)
	}

	// q substring over detail.
	_, total, _ = auditGet(t, srv, "?q=via=telegram")
	if total != 1 {
		t.Fatalf("q=via=telegram want 1, got %v", total)
	}

	// plane=A: ai_add_domain + service.start = 2.
	_, total, _ = auditGet(t, srv, "?plane=A")
	if total != 2 {
		t.Fatalf("plane=A want 2, got %v", total)
	}

	// Pagination: page_size=3 -> pages of 3/3/1, page 2 offset correct.
	ev, total, page := auditGet(t, srv, "?page_size=3&page=2")
	if total != 7 || page != 2 || len(ev) != 3 {
		t.Fatalf("paging want total=7 page=2 len=3, got %v/%v/%d", total, page, len(ev))
	}
	if ev[0]["action"] != "ai_add_domain" {
		t.Fatalf("page-2 head mismatch: %v", ev[0]["action"])
	}
	t.Logf("[IMP:8][TestAuditList][RESULT] filters ok total=7 ai=3 vm3=2 vm12=1 paging=3/3/1")
	printIMPFromBuf(t, buf)
}

func actions(ev []map[string]any) []string {
	out := make([]string, 0, len(ev))
	for _, e := range ev {
		out = append(out, e["action"].(string))
	}
	return out
}

func TestAudit_VMIDExtractionAndJSONFilter(t *testing.T) {
	srv, buf := newServer(t)
	// JSON-dialect detail (ssh_session_open writes {"vm_id":N,...}).
	if err := audit.Append(srv.store.DB, srv.logger, audit.Entry{
		Plane: audit.PlaneB, Action: "ssh_session_open", Success: true,
		Detail: `{"vm_id":3,"rows":24,"cols":80}`,
	}); err != nil {
		t.Fatalf("append: %v", err)
	}
	// Filter by vm_id=3 must match the JSON dialect.
	ev, total, _ := auditGet(t, srv, "?vm_id=3")
	if total != 1 || len(ev) != 1 {
		t.Fatalf("vm_id=3 want 1, got %v", total)
	}
	if ev[0]["vm_id"] == nil {
		t.Fatalf("vm_id not extracted into event: %v", ev[0])
	}
	// vm=12 must NOT match vm_id=3.
	_, total, _ = auditGet(t, srv, "?vm_id=12")
	if total != 0 {
		t.Fatalf("vm_id=12 want 0, got %v", total)
	}
	t.Logf("[IMP:8][TestAuditVMID][RESULT] json-filter=1 extracted=%v no-cross-match", ev[0]["vm_id"])
	printIMPFromBuf(t, buf)
}

func TestAudit_ConfigMutationsAudited(t *testing.T) {
	srv, buf := newServer(t)
	// The user's exact scenario: toggle VM channels, add a domain — must land in the journal.
	vmID, _ := srv.store.CreateVM(context.Background(), store.VM{Name: "Kate", Hostname: "k", PortSSH: 22})
	chID, _ := srv.store.CreateChannel(context.Background(), store.Channel{Type: "telegram", Name: "tg", Enabled: true})
	req := httptest.NewRequest(http.MethodPut, "/api/vms/"+itoa64(vmID)+"/alert-channels",
		strings.NewReader(`{"channel_ids":[`+itoa64(chID)+`]}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("setVMAlertChannels: %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodPost, "/api/domains", strings.NewReader(`{"name":"fix.example"}`))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("createDomain: %d %s", w.Code, w.Body.String())
	}
	for _, want := range []string{"vm_channels_set", "domain_create"} {
		ev, total, _ := auditGet(t, srv, "?q="+want)
		if total != 1 {
			t.Fatalf("%s not audited properly: total=%v", want, total)
		}
		if total == 1 && want == "vm_channels_set" && ev[0]["vm_id"] == nil {
			t.Fatalf("vm_channels_set missing extracted vm_id: %+v", ev[0])
		}
	}
	t.Logf("[IMP:8][TestAuditConfig][RESULT] vm_channels_set+domain_create audited")
	printIMPFromBuf(t, buf)
}

func TestAudit_DomainFilter(t *testing.T) {
	srv, buf := newServer(t)
	// domain_create writes "domain_id=N name=x" into detail.
	req := httptest.NewRequest(http.MethodPost, "/api/domains", strings.NewReader(`{"name":"dfilter.example"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("createDomain: %d %s", w.Code, w.Body.String())
	}
	var domID int64
	_ = srv.store.DB.QueryRow(`SELECT id FROM domains WHERE name='dfilter.example'`).Scan(&domID)

	// Filter by that domain id: exactly 1 event (domain_create), with extracted domain_id.
	ev, total, _ := auditGet(t, srv, "?domain_id="+itoa64(domID))
	if total != 1 || len(ev) != 1 {
		t.Fatalf("domain_id=%d want 1, got %v", domID, total)
	}
	if ev[0]["domain_id"] == nil {
		t.Fatalf("domain_id not extracted: %+v", ev[0])
	}
	// A neighbor id must not match.
	_, total, _ = auditGet(t, srv, "?domain_id=999")
	if total != 0 {
		t.Fatalf("domain_id=999 want 0, got %v", total)
	}
	t.Logf("[IMP:8][TestAuditDomain][RESULT] filter=1 extracted=%v no-cross-match", ev[0]["domain_id"])
	printIMPFromBuf(t, buf)
}

func TestAudit_AnyDirectionFilter(t *testing.T) {
	srv, buf := newServer(t)
	seedAudit(t, srv) // 7 events: vm=3, vm=12 rows + auth/tg/domain/service

	// vm_id=any: every event touching SOME server (ai_action_run x2, ssh, ai_set? -> seeded set has 3 vm rows).
	_, total, _ := auditGet(t, srv, "?vm_id=any")
	// seeded: ai_action_run(vm=3), ai_action_run(vm=12), ssh_session_open(vm=3) = 3
	if total != 3 {
		t.Fatalf("vm_id=any want 3, got %v", total)
	}
	// domain_id=any: ai_add_domain (target domain) = 1.
	_, total, _ = auditGet(t, srv, "?domain_id=any")
	if total != 1 {
		t.Fatalf("domain_id=any want 1, got %v", total)
	}
	// auth.login must NOT appear in the VM direction.
	ev, _, _ := auditGet(t, srv, "?vm_id=any")
	for _, e := range ev {
		if e["action"] == "auth.login" {
			t.Fatalf("auth.login leaked into vm direction: %+v", e)
		}
	}
	t.Logf("[IMP:8][TestAuditAny][RESULT] vm-any=3 domain-any=1 auth-excluded")
	printIMPFromBuf(t, buf)
}

func TestAudit_ClearAllAndBefore(t *testing.T) {
	srv, buf := newServer(t)
	seedAudit(t, srv)

	// Clear BEFORE adding a marker: delete everything, then add one fresh row and verify the
	// chain still verifies (kept rows keep their stored hashes).
	req := httptest.NewRequest(http.MethodDelete, "/api/audit", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !contains(rec.Body.String(), `"deleted":7`) {
		t.Fatalf("clear-all failed: %d %s", rec.Code, rec.Body.String())
	}
	if err := audit.Append(srv.store.DB, srv.logger, audit.Entry{Plane: audit.PlaneA, Action: "service.stop", Success: true}); err != nil {
		t.Fatalf("append after clear: %v", err)
	}
	if err := audit.VerifyChain(srv.store.DB); err != nil {
		t.Fatalf("chain broken after clear-all: %v", err)
	}

	// before=2030-01-01 deletes everything (all rows are older).
	req = httptest.NewRequest(http.MethodDelete, "/api/audit?before=2030-01-01", nil)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("clear-before failed: %d %s", rec.Code, rec.Body.String())
	}
	_, total, _ := auditGet(t, srv, "")
	if total != 0 {
		t.Fatalf("want 0 after clear-before, got %v", total)
	}
	t.Logf("[IMP:9][TestAuditClear][RESULT] clear-all=7 chain-ok clear-before=0")
	printIMPFromBuf(t, buf)
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
