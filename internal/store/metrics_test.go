// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): Metrics,Downsampling; TECH(8): go test]
// @purpose Verify RecordSamples round-trip via MetricSeries, resolution auto-selection, and that
//
//	Downsample aggregates raw>7d into hourly 1h rows and deletes the raw source.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, metrics, record, series, downsampling, resolution, raw, 1h
package store

import (
	"context"
	"testing"
	"time"
)

func TestMetrics_RecordAndSeries(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, VM{Name: "m", Hostname: "h", PortSSH: 22})

	if err := s.RecordSamples(ctx, vmID, map[string]float64{"mem_used_mb": 100, "load1": 0.5}); err != nil {
		t.Fatalf("RecordSamples: %v", err)
	}
	if err := s.RecordSamples(ctx, vmID, map[string]float64{"mem_used_mb": 200, "load1": 0.7}); err != nil {
		t.Fatalf("RecordSamples 2: %v", err)
	}

	// latest value
	v, ok, err := s.LatestMetricValue(ctx, vmID, "mem_used_mb")
	if err != nil || !ok || v != 200 {
		t.Fatalf("latest mem: got %v ok=%v err=%v (want 200)", v, ok, err)
	}

	// series (24h span -> raw)
	now := time.Now()
	ser, err := s.MetricSeries(ctx, vmID, "mem_used_mb", now.Add(-24*time.Hour), now)
	if err != nil {
		t.Fatalf("series: %v", err)
	}
	if len(ser) != 2 || ser[0].Value != 100 || ser[1].Value != 200 {
		t.Fatalf("series order/values wrong: %+v", ser)
	}
}

func TestMetrics_Downsample(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, VM{Name: "m2", Hostname: "h", PortSSH: 22})

	// Insert raw rows 10 days ago (3 within the same hour -> avg; should collapse to one 1h row).
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	for _, v := range []float64{100, 200, 300} {
		if _, err := s.DB.ExecContext(ctx,
			`INSERT INTO metric_samples (vm_id, metric_name, value, resolution, ts) VALUES (?,?,?, 'raw', ?)`,
			vmID, "mem_used_mb", v, old.Format(time.RFC3339Nano)); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	// Insert a recent raw row (within keep) -> must survive.
	if err := s.RecordSamples(ctx, vmID, map[string]float64{"mem_used_mb": 42}); err != nil {
		t.Fatalf("recent record: %v", err)
	}

	removed, err := s.Downsample(ctx, 7*24*time.Hour)
	if err != nil {
		t.Fatalf("downsample: %v", err)
	}
	if removed != 3 {
		t.Fatalf("raw_removed: got %d, want 3", removed)
	}

	// Recent raw survives.
	now := time.Now()
	ser, _ := s.MetricSeries(ctx, vmID, "mem_used_mb", now.Add(-24*time.Hour), now)
	if len(ser) != 1 || ser[0].Value != 42 {
		t.Fatalf("recent raw not preserved: %+v", ser)
	}
	// The old hour aggregated to one 1h row with avg=200.
	oldSer, _ := s.MetricSeries(ctx, vmID, "mem_used_mb", now.Add(-30*24*time.Hour), now.Add(-9*24*time.Hour))
	if len(oldSer) != 1 || oldSer[0].Value != 200 {
		t.Fatalf("old hourly aggregate wrong: %+v", oldSer)
	}
}
