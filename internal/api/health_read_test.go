// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): HealthAPI; TECH(8): go test,httptest]
// @purpose Verify GET /api/vms/{id}/results and /api/vms/{id}/health, incl. 404 + empty arrays.
//
//	Covers the auto-provisioned system checks coexisting with manual ones: results list every
//	check (our row found by check_id), health skips disabled system checks.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, results, health, endpoint, httptest, score, 404, system checks
// STRUCTURE: ▶ ┌server┐ → POST vm → ⚡ disable system checks → POST tcp check → ⊕ insert result → ○ GET results/health → 〈assert〉
package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// region FUNC_test_VMResultsAndHealth [DOMAIN(7): Testing; CONCEPT(7): HealthAPI; TECH(6): httptest]
// @purpose Verify the read endpoints reflect exactly the manual check's stored result when the
//
//	auto-provisioned system checks are disabled (deterministic health score of 100).
//
// @complexity 5
// endregion FUNC_test_VMResultsAndHealth
func TestHTTP_VMResultsAndHealth(t *testing.T) {
	srv, buf := newServer(t)

	// Create VM (createVM auto-provisions system liveness+exposures checks).
	rec := do(srv, http.MethodPost, "/api/vms", `{"name":"web1","hostname":"10.0.0.1","port_ssh":22}`)
	var vm struct {
		ID int64 `json:"id"`
	}
	decode(t, rec, &vm)

	// BUG_FIX_CONTEXT: since auto-provisioning landed, a fresh VM carries 2 system checks
	// (liveness + exposures) that never ran; they drag the health score below 100 and broke
	// the old 1-row expectation (the historical "flake"). Disable them via the store so the
	// assertions below exercise exactly the manual tcp check.
	if _, err := srv.store.DB.ExecContext(context.Background(),
		`UPDATE checks SET enabled=0 WHERE vm_id=? AND system=1`, vm.ID); err != nil {
		t.Fatalf("disable system checks: %v", err)
	}

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

	// GET /api/vms/{id}/results -> array (not null); our tcp row is found by check_id
	// (disabled system checks are still listed by the read model).
	rec = do(srv, http.MethodGet, "/api/vms/"+strconv.FormatInt(vm.ID, 10)+"/results", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("results want 200, got %d", rec.Code)
	}
	if !strings.HasPrefix(strings.TrimSpace(rec.Body.String()), "[") {
		t.Fatalf("results should be a JSON array, got %s", rec.Body.String())
	}
	var rows []map[string]any
	decode(t, rec, &rows)
	if len(rows) < 1 {
		t.Fatalf("results want >=1 row, got %d", len(rows))
	}
	var ours map[string]any
	for _, r := range rows {
		if v, ok := r["check_id"].(float64); ok && int64(v) == chk.ID {
			ours = r
		}
	}
	if ours == nil {
		t.Fatalf("results must contain the tcp check %d, got %s", chk.ID, rec.Body.String())
	}
	if ours["latest_status"] != "ok" {
		t.Fatalf("tcp check latest_status want ok, got %v", ours["latest_status"])
	}

	// GET /api/vms/{id}/health -> score 100, status ok (disabled system checks are skipped).
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

// endregion FUNC_test_VMResultsAndHealth
