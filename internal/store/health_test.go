// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): HealthReadModel; TECH(8): go test]
// @purpose Verify LatestResultsForVM: one row per check, with/without a result row.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, LatestResultsForVM, VMCheckStatus, health, read model
package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestLatestResultsForVM_WithAndWithoutResults(t *testing.T) {
	log, buf := testLogger(t)
	s, err := Open(filepath.Join(t.TempDir(), "h.sqlite"), log)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	vmID, _ := s.CreateVM(ctx, VM{Name: "v", Hostname: "h", IP: "127.0.0.1", PortSSH: 22})
	c1, _ := s.CreateCheck(ctx, Check{VMID: &vmID, TargetType: "vm", CheckType: "tcp", IntervalSec: 60})
	c2, _ := s.CreateCheck(ctx, Check{VMID: &vmID, TargetType: "vm", CheckType: "http", IntervalSec: 60})

	// Only c1 has a result.
	_, _ = s.InsertCheckResult(ctx, c1, "ok", 12.5, "connected", nil)

	rows, err := s.LatestResultsForVM(ctx, vmID)
	if err != nil {
		t.Fatalf("LatestResultsForVM: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 rows (one per check), got %d", len(rows))
	}
	byCheck := map[int64]VMCheckStatus{}
	for _, r := range rows {
		byCheck[r.CheckID] = r
	}
	if byCheck[c1].LatestStatus != "ok" || byCheck[c1].LatestLatency != 12.5 {
		t.Fatalf("c1 latest mismatch: %+v", byCheck[c1])
	}
	if byCheck[c2].LatestStatus != "" {
		t.Fatalf("c2 should have empty status (no run yet), got %q", byCheck[c2].LatestStatus)
	}

	// Unknown VM -> empty slice.
	rows, _ = s.LatestResultsForVM(ctx, 9999)
	if len(rows) != 0 {
		t.Fatalf("unknown vm want 0 rows, got %d", len(rows))
	}

	printIMPFromBuf(t, buf)
}
