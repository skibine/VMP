// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): NotificationModalAPI; TECH(8): go test,httptest]
// @purpose Verify the modal endpoints: GET /api/notifications/all (filters+page shape),
//
//	DELETE /api/notifications?scope=read|all, GET /api/alerts/all, DELETE /api/alerts — and that
//	the legacy GET /api/notifications still returns a bare array.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, notifications all, alerts all, delete scope, pagination, httptest
// STRUCTURE: ▶ ┌server+seed┐ → ⚡ GET ?unread&kind → ⚡ DELETE ?scope → ◇ shapes → ⎋
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skibine/vm-pulse/internal/store"
)

func TestHTTP_NotificationsAllAndClear(t *testing.T) {
	srv, buf := newServer(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		id, _ := srv.store.CreateNotification(ctx, store.Notification{Title: "a", Kind: "alert"})
		if i < 2 {
			_ = srv.store.MarkNotificationRead(ctx, id)
		}
	}
	srv.store.CreateNotification(ctx, store.Notification{Title: "t", Kind: "test"})

	// Paged history shape: total=4, unread=1.
	rec := httptest.NewRequest("", "/api/notifications/all?page_size=2&page=1", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, rec)
	if w.Code != http.StatusOK {
		t.Fatalf("all: %d %s", w.Code, w.Body.String())
	}
	var body struct {
		Items []store.Notification `json:"items"`
		Total int                  `json:"total"`
		Page  int                  `json:"page"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Total != 4 || len(body.Items) != 2 || body.Page != 1 {
		t.Fatalf("shape mismatch: total=%d items=%d page=%d", body.Total, len(body.Items), body.Page)
	}

	// unread=1 filter.
	req := httptest.NewRequest(http.MethodGet, "/api/notifications/all?unread=1", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var ub struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &ub)
	if ub.Total != 2 { // 1 unread alert + unread test
		t.Fatalf("unread want 2, got %d", ub.Total)
	}

	// Legacy dropdown endpoint: bare array.
	req = httptest.NewRequest(http.MethodGet, "/api/notifications", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var legacy []store.Notification
	if err := json.Unmarshal(w.Body.Bytes(), &legacy); err != nil {
		t.Fatalf("legacy shape broken: %v (%s)", err, w.Body.String())
	}

	// DELETE read-only: 2 rows.
	req = httptest.NewRequest(http.MethodDelete, "/api/notifications", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var del struct {
		Deleted int `json:"deleted"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &del)
	if del.Deleted != 2 {
		t.Fatalf("delete-read want 2, got %d", del.Deleted)
	}
	// DELETE all: the rest.
	req = httptest.NewRequest(http.MethodDelete, "/api/notifications?scope=all", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &del)
	if del.Deleted != 2 {
		t.Fatalf("delete-all want 2, got %d", del.Deleted)
	}
	t.Logf("[IMP:8][TestNotifAllAPI][RESULT] total=4 unread=2 delread=2 delall=2")
	printIMPFromBuf(t, buf)
}

func TestHTTP_AlertsAllAndClear(t *testing.T) {
	srv, buf := newServer(t)
	ctx := context.Background()
	ruleID, _ := srv.store.CreateAlertRule(ctx, store.AlertRule{Name: "r", TriggerStatus: "critical", Severity: "critical"})
	vmID, _ := srv.store.CreateVM(ctx, store.VM{Name: "v", Hostname: "h", PortSSH: 22})
	for i := 0; i < 3; i++ {
		sev := "critical"
		if i == 2 {
			sev = "warning"
		}
		_, _ = srv.store.InsertAlert(ctx, store.Alert{RuleID: ruleID, VMID: &vmID, Severity: sev, Message: "m"})
	}

	req := httptest.NewRequest(http.MethodGet, "/api/alerts/all?severity=critical", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var body struct {
		Alerts []store.Alert `json:"alerts"`
		Total  int           `json:"total"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Total != 2 || len(body.Alerts) != 2 {
		t.Fatalf("critical want 2, got %d/%d", len(body.Alerts), body.Total)
	}

	// vm filter.
	req = httptest.NewRequest(http.MethodGet, "/api/alerts/all?vm_id="+itoa64(vmID), nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Total != 3 {
		t.Fatalf("vm filter want 3, got %d", body.Total)
	}

	// unack filter: no alert is acknowledged yet -> same count (tab badge source).
	req = httptest.NewRequest(http.MethodGet, "/api/alerts/all?unack=1", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Total != 3 {
		t.Fatalf("unack want 3, got %d", body.Total)
	}

	// Ack flow: ack one by click, ack-all the rest; unack filter shrinks to 0.
	req = httptest.NewRequest(http.MethodGet, "/api/alerts/all?unack=1", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Total != 3 {
		t.Fatalf("unack start want 3, got %d", body.Total)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/alerts/2/ack", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("ack: %d %s", w.Code, w.Body.String())
	}
	req = httptest.NewRequest(http.MethodGet, "/api/alerts/all?unack=1", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Total != 2 {
		t.Fatalf("after one ack want 2, got %d", body.Total)
	}
	req = httptest.NewRequest(http.MethodPost, "/api/alerts/ack-all", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	req = httptest.NewRequest(http.MethodGet, "/api/alerts/all?unack=1", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Total != 0 {
		t.Fatalf("after ack-all want 0, got %d", body.Total)
	}
	t.Logf("[IMP:8][TestAlertsAck][RESULT] 3 -> ack one 2 -> ack-all 0")

	// Clear all.
	req = httptest.NewRequest(http.MethodDelete, "/api/alerts", nil)
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	var del struct {
		Deleted int `json:"deleted"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &del)
	if del.Deleted != 3 {
		t.Fatalf("clear want 3, got %d", del.Deleted)
	}
	t.Logf("[IMP:8][TestAlertsAllAPI][RESULT] crit=2 vm=3 clear=3")
	printIMPFromBuf(t, buf)
}
