// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(9): Engine; TECH(8): go test,goroutines]
// @purpose Verify the engine schedules an enabled check, runs it via a mock checker, and
//
//	persists a result; Stop() drains cleanly. Plane A (no credential dependency).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, engine, dispatcher, worker, mock checker, schedule, results
// STRUCTURE: ▶ ┌store+VM+check┐ → ○ Start → ⚡ poll results → 〈>=1 row?〉 → ○ Stop → ⎋ assert
package monitor

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"strings"

	"github.com/skibine/vm-pulse/internal/lddcheck"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

type countingChecker struct{ n int32 }

func (c *countingChecker) Type() string { return "tcp" }
func (c *countingChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	atomic.AddInt32(&c.n, 1)
	return Result{Status: StatusOK, LatencyMS: 1.5, Message: "mock ok", Detail: map[string]any{"target": target}}
}

func TestEngine_RunsAndPersists(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.Setup(slog.LevelDebug, &buf)
	s, err := store.Open(filepath.Join(t.TempDir(), "engine.sqlite"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx0 := context.Background()

	vmID, err := s.CreateVM(ctx0, store.VM{Name: "v", Hostname: "localhost", IP: "127.0.0.1", PortSSH: 22})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	chkID, err := s.CreateCheck(ctx0, store.Check{
		VMID: &vmID, TargetType: "vm", CheckType: "tcp", IntervalSec: 1, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateCheck: %v", err)
	}

	cc := &countingChecker{}
	reg := NewRegistry(cc)
	eng := New(s, reg, logger, Options{PoolSize: 2, TickEvery: 100 * time.Millisecond, RetentionDays: 30})

	runCtx, cancel := context.WithCancel(context.Background())
	eng.Start(runCtx)

	// Poll for at least one result within 3s.
	deadline := time.Now().Add(3 * time.Second)
	var got []store.CheckResult
	for time.Now().Before(deadline) {
		got, _ = s.ListRecentResults(ctx0, chkID, 5)
		if len(got) >= 1 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	cancel()
	eng.Stop()

	if len(got) == 0 {
		t.Fatal("expected at least one result, got none")
	}
	if got[0].Status != string(StatusOK) {
		t.Fatalf("first result status want ok, got %s", got[0].Status)
	}
	if got[0].LatencyMS != 1.5 {
		t.Fatalf("latency want 1.5, got %v", got[0].LatencyMS)
	}
	if atomic.LoadInt32(&cc.n) < 1 {
		t.Fatal("mock checker was never invoked")
	}

	// Semantic Trace anchor.
	out := buf.String()
	saw := false
	for _, line := range strings.Split(out, "\n") {
		if imp, ok := lddcheck.IMPValue(line); ok && imp >= 7 {
			t.Log(line)
			if imp >= 8 && strings.Contains(line, "RESULT") {
				saw = true
			}
		}
	}
	if !saw {
		t.Errorf("Anti-Illusion: missing [IMP:8][runCheck][RESULT] in logs")
	}
}
