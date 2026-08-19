// region MODULE_CONTRACT [DOMAIN(8): Observability; CONCEPT(8): MetricsAPI; TECH(8): net/http]
// @purpose Expose per-VM metrics: the chart time-series (auto-resolution by range) and a toggle to
//
//	enable/disable the pull-poller for a VM.
//
// @io registerMetrics(mux, store, logger); routes GET /metrics?range=, PUT /metrics {enabled}
// @invariants
//   - GET returns per-metric series + the latest sample; resolution is chosen by the range span.
//   - PUT only flips metrics_enabled (does not require a full VM body).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: metrics api, series, charts, range, toggle, metrics_enabled, latest, downsample
// STRUCTURE: ▶ ┌{id}┐ → ◇ GET: Series(range)+latest | PUT: SetMetricsEnabled → ⎋ JSON
package api

import (
	"context"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/skibine/vmp/internal/logging"
	"github.com/skibine/vmp/internal/store"
)

type metricsAPI struct {
	st     *store.Store
	logger *slog.Logger
}

// metricNamesChart is the fixed set of series returned for the charts block.
var metricNamesChart = []string{"mem_used_mb", "mem_total_mb", "swap_used_mb", "swap_total_mb", "disk_used_gb", "disk_total_gb", "load1", "cpu_pct", "tcp_conns", "proc_count", "net_rx_kbps", "net_tx_kbps"}

func registerMetrics(mux *http.ServeMux, st *store.Store, logger *slog.Logger) {
	a := &metricsAPI{st: st, logger: logger}
	mux.HandleFunc("GET /api/vms/{id}/metrics", a.handleGetMetrics)
	mux.HandleFunc("PUT /api/vms/{id}/metrics", a.handleToggleMetrics)
}

// handleGetMetrics returns chart series + latest sample for a VM.
//
// Query: ?range=1h|24h|7d (default 24h).
func (a *metricsAPI) handleGetMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	dur := parseRange(r.URL.Query().Get("range"))
	to := time.Now()
	from := to.Add(-dur)

	resp := map[string]any{"range": dur.String(), "series": map[string]any{}}
	for _, name := range metricNamesChart {
		pts, err := a.st.MetricSeries(ctx, id, name, from, to)
		if err != nil {
			logging.LDD(a.logger, 9, "getMetrics", "SERIES_FAIL", err.Error())
			continue
		}
		arr := make([][2]any, 0, len(pts))
		for _, p := range pts {
			arr = append(arr, [2]any{p.TS.Unix(), p.Value})
		}
		resp["series"].(map[string]any)[name] = arr
	}

	// latest sample: the most recent rows (all share ~the same ts).
	latest, err := a.latestSample(ctx, id)
	if err != nil {
		logging.LDD(a.logger, 9, "getMetrics", "LATEST_FAIL", err.Error())
	}
	resp["latest"] = latest
	writeJSON(w, http.StatusOK, resp)
}

// handleToggleMetrics enables/disables metrics collection for a VM.
func (a *metricsAPI) handleToggleMetrics(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := a.st.SetMetricsEnabled(r.Context(), id, body.Enabled); err != nil {
		logging.LDD(a.logger, 10, "toggleMetrics", "ERR", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	logging.LDD(a.logger, 8, "toggleMetrics", "SET", strconv.FormatInt(id, 10)+"="+strconv.FormatBool(body.Enabled))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "metrics_enabled": body.Enabled})
}

// latestSample returns the most recent value of each chart metric + the shared timestamp.
func (a *metricsAPI) latestSample(ctx context.Context, vmID int64) (map[string]any, error) {
	out := map[string]any{}
	var ts string
	hasAny := false
	for _, name := range metricNamesChart {
		var v float64
		var t string
		err := a.st.DB.QueryRowContext(ctx,
			`SELECT value, ts FROM metric_samples WHERE vm_id=? AND metric_name=? ORDER BY ts DESC, id DESC LIMIT 1`,
			vmID, name).Scan(&v, &t)
		if err == nil {
			out[name] = v
			ts = t
			hasAny = true
		}
	}
	if !hasAny {
		return nil, nil
	}
	out["ts"] = ts
	return out, nil
}

// parseRange maps the ?range= token to a duration (default 24h).
func parseRange(s string) time.Duration {
	switch s {
	case "1h":
		return time.Hour
	case "7d":
		return 7 * 24 * time.Hour
	default:
		return 24 * time.Hour
	}
}
