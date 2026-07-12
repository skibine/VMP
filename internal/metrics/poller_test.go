// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): PullPoller; TECH(8): go test]
// @purpose Verify the poller collects+records for metrics-enabled VMs, skips disabled ones, and is
//
//	tolerant to collection errors (one failing VM does not stop the others). Prints [IMP:7-10].
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, poller, metrics, collect, fake, error-tolerant, enabled, skip
package metrics

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// fakeCollector records which VMs it was asked to collect and can be made to fail for some.
type fakeCollector struct {
	mu      sync.Mutex
	called  []int64
	failFor map[int64]bool
}

func (f *fakeCollector) Collect(_ context.Context, vmID int64) (map[string]float64, error) {
	f.mu.Lock()
	f.called = append(f.called, vmID)
	fail := f.failFor[vmID]
	f.mu.Unlock()
	if fail {
		return nil, errFake("dial failed")
	}
	return map[string]float64{"mem_used_mb": 123, "load1": 0.3}, nil
}

type errFake string

func (e errFake) Error() string { return string(e) }

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	buf := &bytes.Buffer{}
	logr := logging.Setup(slog.LevelDebug, buf)
	s, err := store.Open(filepath.Join(t.TempDir(), "metrics.sqlite"), logr)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestPoller_RecordsEnabledSkipsDisabledAndTolerant(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	// enabled VMs
	en1, _ := s.CreateVM(ctx, store.VM{Name: "e1", Hostname: "h", PortSSH: 22, MetricsEnabled: true})
	en2, _ := s.CreateVM(ctx, store.VM{Name: "e2", Hostname: "h", PortSSH: 22, MetricsEnabled: true})
	// disabled VM
	_, _ = s.CreateVM(ctx, store.VM{Name: "dis", Hostname: "h", PortSSH: 22, MetricsEnabled: false})

	fc := &fakeCollector{failFor: map[int64]bool{en1: true}} // en1 fails, en2 succeeds
	p := New(s, fc, logging.Setup(slog.LevelDebug, &bytes.Buffer{})).WithWorkers(2)

	p.cycle(ctx) // run one cycle directly (deterministic)

	// Only the two enabled VMs were attempted; the disabled one never.
	fc.mu.Lock()
	got := append([]int64{}, fc.called...)
	fc.mu.Unlock()
	if len(got) != 2 {
		t.Fatalf("expected 2 collections (enabled only), got %d: %v", len(got), got)
	}
	for _, id := range got {
		if id != en1 && id != en2 {
			t.Fatalf("unexpected vm collected: %d", id)
		}
	}

	// en2 succeeded -> a metric sample row exists; en1 failed -> none.
	v, ok, _ := s.LatestMetricValue(ctx, en2, "mem_used_mb")
	if !ok || v != 123 {
		t.Fatalf("en2 not recorded: v=%v ok=%v", v, ok)
	}
	if ok, _ := hasAny(ctx, s, en1); ok {
		t.Fatalf("en1 should have no samples (collection failed)")
	}
}

func TestPoller_DownsampleRunsOnce(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, store.VM{Name: "d", Hostname: "h", PortSSH: 22, MetricsEnabled: true})
	// seed an old raw row beyond retention
	old := time.Now().UTC().Add(-10 * 24 * time.Hour)
	_, _ = s.DB.ExecContext(ctx,
		`INSERT INTO metric_samples (vm_id, metric_name, value, resolution, ts) VALUES (?,?,?, 'raw', ?)`,
		vmID, "mem_used_mb", 50.0, old.Format(time.RFC3339Nano))

	p := New(s, &fakeCollector{}, logging.Setup(slog.LevelDebug, &bytes.Buffer{}))
	if err := p.downsample(ctx); err != nil {
		t.Fatalf("downsample: %v", err)
	}
	// raw > 7d should be gone (aggregated to 1h)
	ok, _ := hasAny(ctx, s, vmID)
	if ok {
		t.Fatalf("raw row should have been downsampled away")
	}
}

// hasAny reports whether the VM has any raw metric_samples row.
func hasAny(ctx context.Context, s *store.Store, vmID int64) (bool, error) {
	var n int
	err := s.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM metric_samples WHERE vm_id=? AND resolution='raw'`, vmID).Scan(&n)
	return n > 0, err
}
