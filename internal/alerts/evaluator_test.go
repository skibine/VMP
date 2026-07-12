// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(9]: Evaluator; TECH(8]: go test]
// @purpose Verify the evaluator fires an alert (delivering via a capture channel) and
//
//	respects cooldown on the second pass.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, evaluator, fire, cooldown, capture channel, delivery
// STRUCTURE: ▶ ┌store(rule+check+result+channel)┐ → ○ evaluate → 〈fired? cooldown?〉 → ⎋ assert
package alerts

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/skibine/vm-pulse/internal/lddcheck"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

type captureChannel struct {
	mu   sync.Mutex
	msgs []Message
}

func (*captureChannel) Type() string { return "capture" }
func (c *captureChannel) Deliver(_ context.Context, _ map[string]any, msg Message) error {
	c.mu.Lock()
	c.msgs = append(c.msgs, msg)
	c.mu.Unlock()
	return nil
}
func (c *captureChannel) count() int { c.mu.Lock(); defer c.mu.Unlock(); return len(c.msgs) }

func TestEvaluator_FiresAndCooldowns(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.Setup(slog.LevelDebug, &buf)
	s, err := store.Open(filepath.Join(t.TempDir(), "ev.sqlite"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	// VM + check + a critical result.
	vmID, _ := s.CreateVM(ctx, store.VM{Name: "v", Hostname: "h", IP: "127.0.0.1", PortSSH: 22})
	chkID, _ := s.CreateCheck(ctx, store.Check{VMID: &vmID, TargetType: "vm", CheckType: "tcp", IntervalSec: 60, Enabled: true})
	_, _ = s.InsertCheckResult(ctx, chkID, "critical", 0, "refused", nil)

	// Rule: any check type, trigger critical, big cooldown.
	rid, _ := s.CreateAlertRule(ctx, store.AlertRule{
		Name: "down", TriggerStatus: "critical", Severity: "critical", CooldownSec: 3600, Enabled: true,
	})
	// Channel of type "capture" attached.
	cid, _ := s.CreateChannel(ctx, store.Channel{Type: "capture", Name: "cap", Enabled: true})
	_ = s.AttachChannel(ctx, rid, cid)

	cap := &captureChannel{}
	reg := NewRegistry(cap)
	ev := New(s, reg, logger, 1)
	ev.ctx = context.Background() // evaluate() reads e.ctx

	// First pass: should fire exactly once.
	ev.evaluate()
	alerts, _ := s.ListAlerts(ctx, 10)
	if len(alerts) != 1 {
		t.Fatalf("after 1st evaluate want 1 alert, got %d", len(alerts))
	}
	if cap.count() != 1 {
		t.Fatalf("capture channel want 1 delivery, got %d", cap.count())
	}
	// delivery_log recorded ok for the channel.
	dl := alerts[0].DeliveryLog
	entry, ok := dl[strconv.FormatInt(cid, 10)].(map[string]any)
	if !ok || entry["ok"] != true {
		t.Fatalf("delivery_log not ok: %#v", dl)
	}

	// Second pass within cooldown: no new alert, no new delivery.
	ev.evaluate()
	alerts, _ = s.ListAlerts(ctx, 10)
	if len(alerts) != 1 {
		t.Fatalf("cooldown broken: want still 1 alert, got %d", len(alerts))
	}
	if cap.count() != 1 {
		t.Fatalf("cooldown broken: want still 1 delivery, got %d", cap.count())
	}

	// Semantic Trace anchor.
	saw := false
	for _, line := range strings.Split(buf.String(), "\n") {
		if imp, ok := lddcheck.IMPValue(line); ok && imp >= 9 && strings.Contains(line, "FIRED") {
			saw = true
			t.Log(line)
		}
	}
	if !saw {
		t.Error("Anti-Illusion: missing [IMP:9][fire][FIRED] in logs")
	}
}
