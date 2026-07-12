// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): HealthAPI; TECH(8): go test,httptest]
// @purpose Verify GET /api/vms/{id}/results and /api/vms/{id}/health, incl. 404 + empty arrays.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, results, health, endpoint, httptest, score, 404
// STRUCTURE: ▶ ┌server┐ → POST vm+check → ⊕ insert result → ○ GET results/health → 〈assert〉
package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestHTTP_VMResultsAndHealth(t *testing.T) {
	srv, buf := newServer(t)

	// Create VM.
	rec := do(srv, http.MethodPost, "/api/vms", `{"name":"web1","hostname":"10.0.0.1","port_ssh":22}`)
	var vm struct {
		ID int64 `json:"id"`
	}
	decode(t, rec, &vm)

	// Create a check.
	rec = do(srv, http.MethodPost, "/api/checks",
		`{"vm_id":`+strconv.FormatInt(vm.ID, 10)+`,"target_type":"vm","check_type":"tcp","interval_sec":60}`)
	var chk struct {
		ID int64 `json:"id"`
	}
	decode(t, rec, &chk)

	// Insert a result directly via the store (engine integration is slice 02).
	if _, err := srv.store.InsertCheckResult(context.Background(), chk.ID, "ok", 9.5, "connected", nil); err != nil {
		t.Fatalf("InsertCheckResult: %v", err)
	}

	// GET /api/vms/{id}/results -> array (not null).
	rec = do(srv, http.MethodGet, "/api/vms/"+strconv.FormatInt(vm.ID, 10)+"/results", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("results want 200, got %d", rec.Code)
	}
	if !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "[") {
		t.Fatalf("results should be a JSON array, got %s", rec.Body.String())
	}
	var rows []map[string]any
	decode(t, rec, &rows)
	if len(rows) != 1 {
		t.Fatalf("results want 1 row, got %d", len(rows))
	}
	if rows[0]["latest_status"] != "ok" {
		t.Fatalf("latest_status want ok, got %v", rows[0]["latest_status"])
	}

	// GET /api/vms/{id}/health -> score 100, status ok.
	rec = do(srv, http.MethodGet, "/api/vms/"+strconv.FormatInt(vm.ID, 10)+"/health", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("health want 200, got %d", rec.Code)
	}
	var score map[string]any
	decode(t, rec, &score)
	if score["status"] != "ok" {
		t.Fatalf("health status want ok, got %v", score["status"])
	}
	if int(score["score"].(float64)) != 100 {
		t.Fatalf("health score want 100, got %v", score["score"])
	}

	// Unknown VM -> 404.
	rec = do(srv, http.MethodGet, "/api/vms/9999/health", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown vm health want 404, got %d", rec.Code)
	}

	printIMPFromBuf(t, buf)
	assertContains(t, buf, "[IMP:7][vmHealth][PROBE]")
}
