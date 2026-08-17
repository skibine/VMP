// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): AlertHistory; TECH(8): go test]
// @purpose Verify ListAlertsFiltered (severity/vm/date filters, paging, total) and DeleteAlerts
//
//	(all / before-date).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, alerts, filtered, severity, vm, date, delete, before
package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestAlertsFilteredAndDelete(t *testing.T) {
	log, buf := testLogger(t)
	s, err := Open(filepath.Join(t.TempDir(), "af.sqlite"), log)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	vm1, _ := s.CreateVM(ctx, VM{Name: "one", Hostname: "h1", PortSSH: 22})
	vm2, _ := s.CreateVM(ctx, VM{Name: "two", Hostname: "h2", PortSSH: 22})
	ruleID, err := s.CreateAlertRule(ctx, AlertRule{Name: "r", TriggerStatus: "critical", Severity: "critical"})
	if err != nil {
		t.Fatalf("CreateAlertRule: %v", err)
	}
	seed := []Alert{
		{RuleID: ruleID, Severity: "critical", VMID: &vm1, Message: "m1"},
		{RuleID: ruleID, Severity: "warning", VMID: &vm1, Message: "m2"},
		{RuleID: ruleID, Severity: "critical", VMID: &vm2, Message: "m3"},
		{RuleID: ruleID, Severity: "warning", VMID: nil, Message: "m4-domain"},
	}
	for _, a := range seed {
		if _, err := s.InsertAlert(ctx, a); err != nil {
			t.Fatalf("InsertAlert: %v", err)
		}
	}

	_, total, _ := s.ListAlertsFiltered(ctx, AlertFilter{})
	if total != 4 {
		t.Fatalf("total want 4, got %d", total)
	}
	_, total, _ = s.ListAlertsFiltered(ctx, AlertFilter{Severity: "critical"})
	if total != 2 {
		t.Fatalf("critical want 2, got %d", total)
	}
	items, total, _ := s.ListAlertsFiltered(ctx, AlertFilter{VMID: &vm1})
	if total != 2 || len(items) != 2 {
		t.Fatalf("vm1 want 2, got %d/%d", len(items), total)
	}
	// Future from-date: nothing (all rows are 'now').
	_, total, _ = s.ListAlertsFiltered(ctx, AlertFilter{From: "2030-01-01"})
	if total != 0 {
		t.Fatalf("future from want 0, got %d", total)
	}
	// Paging: size 3 -> page 1 has 3, page 2 has 1.
	items, _, _ = s.ListAlertsFiltered(ctx, AlertFilter{Limit: 3, Offset: 0})
	if len(items) != 3 {
		t.Fatalf("page1 want 3, got %d", len(items))
	}
	items, _, _ = s.ListAlertsFiltered(ctx, AlertFilter{Limit: 3, Offset: 3})
	if len(items) != 1 {
		t.Fatalf("page2 want 1, got %d", len(items))
	}

	// before=2030: all deleted; empty before: same.
	n, _ := s.DeleteAlerts(ctx, "2030-01-01")
	if n != 4 {
		t.Fatalf("delete-before-2030 want 4, got %d", n)
	}
	_, total, _ = s.ListAlertsFiltered(ctx, AlertFilter{})
	if total != 0 {
		t.Fatalf("after delete want 0, got %d", total)
	}
	t.Logf("[IMP:8][TestAlertsFiltered][RESULT] total=4 crit=2 vm1=2 paging=3/1 delete=4")
	printIMPFromBuf(t, buf)
}
