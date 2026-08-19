// Package store — time-series metrics (Plane A writes, EAV model) and downsampling.
//
// region MODULE_CONTRACT [DOMAIN(8): Observability; CONCEPT(8): Metrics,Downsampling; TECH(9): SQLite]
// @purpose Persist per-VM metric samples (CPU/RAM/disk/load) written by the pull-poller (and later
// the push-agent), serve chart series, and keep the table small via §5.2 downsampling
// (7 days per-minute 'raw' -> 1/hour '1h', raw deleted).
// @io RecordSamples(vmID, map) ; MetricSeries(vmID, name, range) ; Downsample(ctx)
// @invariants
//   - metric_samples is EAV: (vm_id, ts, metric_name, value, resolution).
//   - resolution is 'raw' (per-minute, <=7d) or '1h' (hourly average, >7d).
//   - Downsample never loses the 1h aggregates: it computes them then deletes only 'raw' source rows.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: metrics, metric_samples, time-series, downsampling, EAV, charts, CPU, RAM, disk, load
// STRUCTURE: ▶ ┌vmID+vals┐ → ⊕ INSERT raw rows ; Series → ○ WHERE range→resolution → ⎷ points ; Downsample → ⚡ AVG/h → ⊕ 1h → ⊖ raw
package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/skibine/vmp/internal/logging"
)

// metricTS formats a time exactly like the metric_samples.ts column DEFAULT
// (strftime('%Y-%m-%dT%H:%M:%fZ','now') -> millisecond precision, literal 'Z'), so range
// bounds compare byte-for-byte against stored rows.
// BUG_FIX_CONTEXT: RFC3339Nano bounds ended with sub-ms digits, and 'Z' > any digit, so a
// sample stored in the same millisecond as the query bound was string-compared as GREATER
// than the bound and silently excluded from series (broke fast machines / CI).
func metricTS(t time.Time) string {
	return t.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")
}

// MetricSample is one EAV row.
type MetricSample struct {
	TS         time.Time
	MetricName string
	Value      float64
}

// RecordSamples writes a set of metric values for a VM at "now" as 'raw' resolution rows.
func (s *Store) RecordSamples(ctx context.Context, vmID int64, samples map[string]float64) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("RecordSamples: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx,
		`INSERT INTO metric_samples (vm_id, metric_name, value, resolution) VALUES (?,?,?,'raw')`)
	if err != nil {
		return fmt.Errorf("RecordSamples: prepare: %w", err)
	}
	defer stmt.Close()
	for name, val := range samples {
		if _, err := stmt.ExecContext(ctx, vmID, name, val); err != nil {
			return fmt.Errorf("RecordSamples: insert %s: %w", name, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("RecordSamples: commit: %w", err)
	}
	return nil
}

// SetMetricsEnabled toggles per-VM metrics collection (pull-poller gate).
func (s *Store) SetMetricsEnabled(ctx context.Context, vmID int64, enabled bool) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE vms SET metrics_enabled=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?`,
		toBoolInt(enabled), vmID)
	if err != nil {
		return fmt.Errorf("SetMetricsEnabled: %w", err)
	}
	return rowsAffected(res, "SetMetricsEnabled", vmID)
}

// ListMetricsEnabledVMs returns non-archived VMs with metrics collection enabled (pull-poller input).
func (s *Store) ListMetricsEnabledVMs(ctx context.Context) ([]VM, error) {
	rows, err := s.DB.QueryContext(ctx, vmSelectCols()+` WHERE metrics_enabled=1 AND archived_at IS NULL ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("ListMetricsEnabledVMs: %w", err)
	}
	defer rows.Close()
	var out []VM
	for rows.Next() {
		v, err := scanVM(rows)
		if err != nil {
			return nil, fmt.Errorf("ListMetricsEnabledVMs scan: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// LatestMetricValue returns the most recent raw value for a vm+metric. ok=false when none.
func (s *Store) LatestMetricValue(ctx context.Context, vmID int64, name string) (float64, bool, error) {
	var v float64
	err := s.DB.QueryRowContext(ctx,
		`SELECT value FROM metric_samples WHERE vm_id=? AND metric_name=? ORDER BY ts DESC, id DESC LIMIT 1`,
		vmID, name).Scan(&v)
	if err == sql.ErrNoRows {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("LatestMetricValue: %w", err)
	}
	return v, true, nil
}

// MetricSeries returns the time series for a vm+metric within [from,to], picking resolution by span:
// spans <= 7 days use 'raw'; longer spans use '1h'. Points are returned oldest-first.
func (s *Store) MetricSeries(ctx context.Context, vmID int64, name string, from, to time.Time) ([]MetricSample, error) {
	res := "raw"
	if to.Sub(from) > 7*24*time.Hour {
		res = "1h"
	}
	// BUG_FIX_CONTEXT: bounds use metricTS (ms precision, same as the column DEFAULT) so that
	// same-millisecond rows are included by the TEXT comparison (see metricTS).
	q := `SELECT ts, value FROM metric_samples
 WHERE vm_id=? AND metric_name=? AND resolution=? AND ts>=? AND ts<=?
 ORDER BY ts ASC, id ASC`
	rows, err := s.DB.QueryContext(ctx, q, vmID, name, res, metricTS(from), metricTS(to))
	if err != nil {
		return nil, fmt.Errorf("MetricSeries: %w", err)
	}
	defer rows.Close()
	var out []MetricSample
	for rows.Next() {
		var tsStr string
		var m MetricSample
		if err := rows.Scan(&tsStr, &m.Value); err != nil {
			return nil, fmt.Errorf("MetricSeries scan: %w", err)
		}
		m.MetricName = name
		m.TS, _ = time.Parse(time.RFC3339Nano, tsStr)
		out = append(out, m)
	}
	return out, rows.Err()
}

// region FUNC_Store_Downsample [DOMAIN(8): Observability; CONCEPT(8): Downsampling; TECH(8): SQLite]
// @purpose Keep metric_samples small: aggregate 'raw' rows older than `keep` into hourly '1h'
//
//	averages, then delete the aggregated raw rows. Idempotent.
//
// @io (ctx, keep time.Duration) -> (rawAggregated int64, error)
// @complexity 6
// @invariants
//   - Only 'raw' rows older than `keep` are touched; '1h' rows are preserved.
//   - A row is aggregated before its raw source is deleted (no data loss on partial failure).
//
// endregion FUNC_Store_Downsample
// STRUCTURE: ▶ ┌cutoff┐ → ◇ raw>7d → ⚡ INSERT 1h=AVG(GROUP BY hour) → ⊖ DELETE raw → ⎷ count
func (s *Store) Downsample(ctx context.Context, keep time.Duration) (int64, error) {
	// metricTS keeps the cutoff byte-comparable with both ms-default rows and Nano-seeded rows.
	cutoff := metricTS(time.Now().UTC().Add(-keep))

	// Aggregate raw rows older than cutoff into hourly buckets (per vm+metric+hour).
	ins, err := s.DB.ExecContext(ctx, `
INSERT INTO metric_samples (vm_id, metric_name, value, resolution, ts)
SELECT vm_id, metric_name, AVG(value), '1h',
       strftime('%Y-%m-%dT%H:00:00.000Z', ts) AS hour
FROM metric_samples
WHERE resolution='raw' AND ts < ?
GROUP BY vm_id, metric_name, hour
HAVING COUNT(*) > 0`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("Downsample: aggregate: %w", err)
	}
	aggregated, _ := ins.RowsAffected()

	// Delete the now-aggregated raw rows.
	del, err := s.DB.ExecContext(ctx,
		`DELETE FROM metric_samples WHERE resolution='raw' AND ts < ?`, cutoff)
	if err != nil {
		return aggregated, fmt.Errorf("Downsample: delete raw: %w", err)
	}
	removed, _ := del.RowsAffected()
	logging.LDD(s.logger, 7, "Downsample", "DONE",
		fmt.Sprintf("aggregated=%d raw_removed=%d cutoff=%s", aggregated, removed, cutoff))
	return removed, nil
}
