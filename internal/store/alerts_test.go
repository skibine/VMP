// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): Alerting; TECH(8): go test]
// @purpose Verify alert rules/channels CRUD, attach, alert insert/list, cooldown query, and
//
//	LatestCheckResults read-model.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, alert_rules, channels, attach, alerts, LatestCheckResults, cooldown
// STRUCTURE: ▶ ┌store┐ → ⊕ rule/channel/attach → ○ alert insert → 〈list/last?〉 → ⎋ assert
package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAlerts_CRUDAndLink(t *testing.T) {
	s, buf := openTestStore(t)
	ctx := context.Background()

	rid, err := s.CreateAlertRule(ctx, AlertRule{
		Name: "down", CheckType: "tcp", TriggerStatus: "critical", Severity: "critical", CooldownSec: 60, Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}
	if _, err := s.CreateAlertRule(ctx, AlertRule{Name: "x", TriggerStatus: "bogus", Severity: "critical"}); err == nil {
		t.Fatal("expected validation error for bad trigger_status")
	}

	cid, err := s.CreateChannel(ctx, Channel{Type: "log", Name: "default"})
	if err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}
	if err := s.AttachChannel(ctx, rid, cid); err != nil {
		t.Fatalf("AttachChannel: %v", err)
	}
	chs, err := s.ListChannelsForRule(ctx, rid)
	if err != nil || len(chs) != 1 {
		t.Fatalf("ListChannelsForRule want 1, got %d (err %v)", len(chs), err)
	}

	rules, _ := s.ListAlertRules(ctx)
	if len(rules) != 1 {
		t.Fatalf("ListAlertRules want 1, got %d", len(rules))
	}

	// Delete rule cascades link.
	if err := s.DeleteAlertRule(ctx, rid); err != nil {
		t.Fatalf("DeleteAlertRule: %v", err)
	}
	chs, _ = s.ListChannelsForRule(ctx, rid)
	if len(chs) != 0 {
		t.Fatalf("cascade: channels for deleted rule want 0, got %d", len(chs))
	}

	printIMPFromBuf(t, buf)
}

func TestAlerts_InsertListCooldown(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	rid, _ := s.CreateAlertRule(ctx, AlertRule{Name: "r", TriggerStatus: "critical", Severity: "critical", CooldownSec: 60})

	id, err := s.InsertAlert(ctx, Alert{RuleID: rid, CheckID: 7, Severity: "critical",
		Message: "down", DeliveryLog: map[string]any{"1": map[string]any{"ok": true}}})
	if err != nil || id == 0 {
		t.Fatalf("InsertAlert: %v (id %d)", err, id)
	}
	list, _ := s.ListAlerts(ctx, 10)
	if len(list) != 1 {
		t.Fatalf("ListAlerts want 1, got %d", len(list))
	}

	ts, ok, err := s.LastAlertFor(ctx, rid, 7)
	if err != nil || !ok || ts == "" {
		t.Fatalf("LastAlertFor want hit, got ts=%q ok=%v err=%v", ts, ok, err)
	}
	_, ok, _ = s.LastAlertFor(ctx, rid, 999)
	if ok {
		t.Fatal("LastAlertFor unknown check want miss")
	}
}

func TestLatestCheckResults_Global(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, VM{Name: "v", Hostname: "h", IP: "127.0.0.1", PortSSH: 22})
	c1, _ := s.CreateCheck(ctx, Check{VMID: &vmID, TargetType: "vm", CheckType: "tcp", IntervalSec: 60, Enabled: true})
	_, _ = s.InsertCheckResult(ctx, c1, "critical", 0, "refused", nil)

	got, err := s.LatestCheckResults(ctx)
	if err != nil {
		t.Fatalf("LatestCheckResults: %v", err)
	}
	if len(got) != 1 || got[0].Status != "critical" || got[0].CheckID != c1 {
		t.Fatalf("unexpected latest results: %+v", got)
	}
	if got[0].VMID == nil || *got[0].VMID != vmID {
		t.Fatalf("vm_id not propagated: %+v", got[0])
	}
}

func openTestStoreAt(t *testing.T) string {
	return filepath.Join(t.TempDir(), "a.sqlite")
}
