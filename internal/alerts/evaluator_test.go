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
	_, _ = s.CreateAlertRule(ctx, store.AlertRule{
		Name: "down", TriggerStatus: "critical", Severity: "critical", CooldownSec: 3600, Enabled: true,
	})
	// Channel of type "capture" attached.
	cid, _ := s.CreateChannel(ctx, store.Channel{Type: "capture", Name: "cap", Enabled: true})
	_ = s.SetVMChannels(ctx, vmID, []int64{cid})

	cap := &captureChannel{}
	reg := NewRegistry(cap)
	ev := New(s, reg, logger, 1)
	ev.ctx = context.Background() // evaluate() reads e.ctx

	// First pass: should fire exactly once.
	ev.evaluate()
	// The fired alert is ALSO in the tamper-evident journal (category "alert", vm extractable).
	var evN int
	var evDetail string
	_ = s.DB.QueryRow(`SELECT COUNT(*), MAX(detail) FROM audit_log WHERE action='alert_fire'`).Scan(&evN, &evDetail)
	if evN != 1 {
		t.Fatalf("want 1 alert_fire audit row, got %d", evN)
	}
	if !strings.Contains(evDetail, "vm="+strconv.FormatInt(vmID, 10)) {
		t.Fatalf("alert_fire detail missing vm: %s", evDetail)
	}
	t.Logf("[IMP:9][TestEvaluator][AUDIT] alert_fire=1 detail=%.80s", evDetail)
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

	// No in-app channel attached -> NO bell notification for the alert (opt-in delivery).
	var notifN int
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM notifications WHERE kind='alert'`).Scan(&notifN)
	if notifN != 0 {
		t.Fatalf("want 0 alert notifications without in-app channel, got %d", notifN)
	}
	// Attach the in-app channel and fire again (new VM/check to get a fresh edge).
	inAppCh, _ := s.CreateChannel(ctx, store.Channel{Type: "in-app", Name: "bell", Enabled: true})
	vm2, _ := s.CreateVM(ctx, store.VM{Name: "v2", Hostname: "h2", IP: "127.0.0.1", PortSSH: 22})
	chk2, _ := s.CreateCheck(ctx, store.Check{VMID: &vm2, TargetType: "vm", CheckType: "tcp", IntervalSec: 60, Enabled: true})
	_ = s.SetVMChannels(ctx, vm2, []int64{inAppCh})
	_, _ = s.InsertCheckResult(ctx, chk2, "critical", 0, "refused", nil)
	ev.evaluate()
	notifN = 0
	_ = s.DB.QueryRow(`SELECT COUNT(*) FROM notifications WHERE kind='alert' AND title LIKE '%v2%'`).Scan(&notifN)
	if notifN != 1 {
		t.Fatalf("want 1 in-app notification for v2, got %d", notifN)
	}
	t.Logf("[IMP:9][TestEvaluator][INAPP] no-channel=0 in-app-attached=1")
}

// region FUNC_test_Evaluator_VMScopeAndRecovery [DOMAIN(7): Testing; CONCEPT(8): Scope; TECH(7): evaluator]
// @purpose A rule with vm_id fires ONLY for that VM; firing is edge-triggered (down once, not
// @purpose every cycle) and a "recovered" message fires when the check returns to ok.
// @complexity 5
// endregion FUNC_test_Evaluator_VMScopeAndRecovery
func TestEvaluator_VMScopeAndRecovery(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.Setup(slog.LevelDebug, &buf)
	s, err := store.Open(filepath.Join(t.TempDir(), "scope.sqlite"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	va, _ := s.CreateVM(ctx, store.VM{Name: "A", Hostname: "a", IP: "127.0.0.1", PortSSH: 22})
	vb, _ := s.CreateVM(ctx, store.VM{Name: "B", Hostname: "b", IP: "127.0.0.2", PortSSH: 22})
	chkA, _ := s.CreateCheck(ctx, store.Check{VMID: &va, TargetType: "vm", CheckType: "tcp", IntervalSec: 60, Enabled: true})
	chkB, _ := s.CreateCheck(ctx, store.Check{VMID: &vb, TargetType: "vm", CheckType: "tcp", IntervalSec: 60, Enabled: true})

	// Rule scoped to VM A only.
	_, _ = s.CreateAlertRule(ctx, store.AlertRule{
		Name: "A-down", CheckType: "tcp", TriggerStatus: "critical", Severity: "critical",
		CooldownSec: 3600, Enabled: true, VMID: &va,
	})
	cid, _ := s.CreateChannel(ctx, store.Channel{Type: "capture", Name: "cap", Enabled: true})
	_ = s.SetVMChannels(ctx, va, []int64{cid})

	cap := &captureChannel{}
	reg := NewRegistry(cap)
	ev := New(s, reg, logger, 1)
	ev.ctx = context.Background()

	// Both checks critical — only VM A (scoped) must fire.
	_, _ = s.InsertCheckResult(ctx, chkA, "critical", 0, "down", nil)
	_, _ = s.InsertCheckResult(ctx, chkB, "critical", 0, "down", nil)
	ev.evaluate()
	if cap.count() != 1 {
		t.Fatalf("scope: want 1 delivery (VM A only), got %d", cap.count())
	}
	// Still critical next cycle — no re-fire (edge + cooldown).
	ev.evaluate()
	if cap.count() != 1 {
		t.Fatalf("edge: want still 1 (no re-fire), got %d", cap.count())
	}
	// VM A recovers — a RECOVERED message fires.
	_, _ = s.InsertCheckResult(ctx, chkA, "ok", 1, "up", nil)
	ev.evaluate()
	if cap.count() != 2 {
		t.Fatalf("recovery: want 2 deliveries, got %d", cap.count())
	}
	cap.mu.Lock()
	last := cap.msgs[len(cap.msgs)-1].Title
	cap.mu.Unlock()
	if !strings.Contains(last, "RECOVERED") {
		t.Errorf("recovery msg should mention RECOVERED, got %q", last)
	}
	t.Logf("[IMP:8][TestScope][RESULT] deliveries=%d lastTitle=%q", cap.count(), last)
}
