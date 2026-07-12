// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): MetricsAPI; TECH(8): go test,httptest]
// @purpose Verify PUT /metrics toggles metrics_enabled and GET /metrics returns chart series.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, metrics api, toggle, series, range
package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/store"
)

func TestMetricsAPI_ToggleAndSeries(t *testing.T) {
	srv, _ := newServer(t)
	ctx := context.Background()

	// create VM (metrics disabled by default)
	rec := do(srv, http.MethodPost, "/api/vms", `{"name":"m","hostname":"h","port_ssh":22}`)
	var vr struct {
		ID int64 `json:"id"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&vr)
	id := vr.ID

	// toggle ON
	rec = do(srv, http.MethodPut, "/api/vms/"+strconv.FormatInt(id, 10)+"/metrics", `{"enabled":true}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("toggle ON: %d %s", rec.Code, rec.Body.String())
	}
	vm, _ := srv.store.GetVM(ctx, id)
	if !vm.MetricsEnabled {
		t.Fatal("metrics_enabled not persisted")
	}

	// seed two samples
	_ = srv.store.RecordSamples(ctx, id, map[string]float64{"mem_used_mb": 100, "mem_total_mb": 1000, "load1": 0.1})
	_ = srv.store.RecordSamples(ctx, id, map[string]float64{"mem_used_mb": 300, "mem_total_mb": 1000, "load1": 0.9})

	// GET series
	rec = do(srv, http.MethodGet, "/api/vms/"+strconv.FormatInt(id, 10)+"/metrics?range=1h", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("get series: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"mem_used_mb"`) || !strings.Contains(body, `"load1"`) {
		t.Fatalf("series missing metrics: %s", body)
	}
	var resp struct {
		Series map[string][][2]any `json:"series"`
		Latest map[string]any      `json:"latest"`
	}
	_ = json.NewDecoder(rec.Body).Decode(&resp)
	if len(resp.Series["mem_used_mb"]) != 2 {
		t.Fatalf("mem_used series want 2 points, got %d", len(resp.Series["mem_used_mb"]))
	}
	if resp.Latest["mem_used_mb"] != 300.0 {
		t.Fatalf("latest mem want 300, got %v", resp.Latest["mem_used_mb"])
	}
}

// keep store import referenced even if helpers cover most usage
var _ = store.VM{}
