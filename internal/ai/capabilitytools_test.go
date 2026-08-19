// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): VMTools,CheckTools; TECH(8): go test]
// @purpose Verify the capability-gap tools: update_vm folds (mute/metrics/tags), SSH-reader
//
//	gating on ai_access, checks CRUD + system-refusal + run_now, alert-rule create/delete,
//	domain mutators (update/reminders/ack), and the mock-reader path.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, vm tools, update vm, mute, ai access gate, check tools, system check, run now, rule, reminder
// STRUCTURE: ▶ ┌store+vm┐ → ○ tool.Run → 〈gate/change/refuse?〉 → ⎋ assert
package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skibine/vmp/internal/store"
)

// fakeReader is a VMDataReader stand-in recording calls.
type fakeReader struct {
	calls   []string
	snapErr error
}

func (f *fakeReader) Snapshot(ctx context.Context, vmID int64) (any, error) {
	f.calls = append(f.calls, "snapshot")
	if f.snapErr != nil {
		return nil, f.snapErr
	}
	return map[string]any{"load1": 0.42, "uptime": "3 days"}, nil
}
func (f *fakeReader) Errors(ctx context.Context, vmID int64, window string) (any, error) {
	f.calls = append(f.calls, "errors:"+window)
	return map[string]any{"entries": []string{}}, nil
}
func (f *fakeReader) Updates(ctx context.Context, vmID int64) (any, error) {
	f.calls = append(f.calls, "updates")
	return map[string]any{"upgradable": 3}, nil
}
func (f *fakeReader) InventoryRefresh(ctx context.Context, vmID int64) (any, error) {
	f.calls = append(f.calls, "inventory")
	return map[string]any{"os": "debian"}, nil
}
func (f *fakeReader) VHosts(ctx context.Context, vmID int64) (any, error) {
	f.calls = append(f.calls, "vhosts")
	return map[string]any{"vhosts": []string{"a.com"}}, nil
}

func TestVMTools_SSHReaderAIAccessGate(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, store.VM{Name: "gate", Hostname: "10.0.0.1", PortSSH: 22})
	fr := &fakeReader{}
	reg := NewRegistry(VMTools(s, fr)...)

	// ai_access OFF -> JSON error, reader NOT called.
	out, err := reg.Run(ctx, "get_vm_snapshot", map[string]any{"vm_id": float64(vmID)})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !strings.Contains(out, "ai access disabled") || len(fr.calls) != 0 {
		t.Fatalf("gate failed: %s calls=%v", out, fr.calls)
	}
	// ai_access ON -> reader runs, data flows.
	_ = s.SetAIEnabled(ctx, vmID, true)
	out, _ = reg.Run(ctx, "get_vm_snapshot", map[string]any{"vm_id": float64(vmID)})
	if !strings.Contains(out, "0.42") || len(fr.calls) != 1 {
		t.Fatalf("reader not used: %s calls=%v", out, fr.calls)
	}
	t.Logf("[IMP:9][TestVMTools][GATE] off=refused on=snapshot ok")
}

func TestVMTools_UpdateVMFolds(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, store.VM{Name: "meta", Hostname: "10.0.0.2", PortSSH: 22})
	reg := NewRegistry(VMTools(s, &fakeReader{})...)

	out, err := reg.Run(ctx, "update_vm", map[string]any{
		"vm_id": float64(vmID), "tags": []any{"prod", "billing"},
		"alert_muted": true, "metrics_enabled": true, "cost_monthly": 4.5, "currency": "EUR",
	})
	if err != nil || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("update_vm: %v %s", err, out)
	}
	vm, _ := s.GetVM(ctx, vmID)
	if len(vm.Tags) != 2 || !vm.MetricsEnabled {
		t.Fatalf("tags/metrics mismatch: %+v", vm)
	}
	muted, _ := s.MutedVMIDs(ctx)
	if !muted[vmID] {
		t.Fatalf("alert_muted fold not applied")
	}
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE action='ai_update_vm'`).Scan(&n)
	if n != 1 {
		t.Fatalf("audit want 1, got %d", n)
	}
	// Nothing-provided call is a no-op.
	out, _ = reg.Run(ctx, "update_vm", map[string]any{"vm_id": float64(vmID)})
	if !strings.Contains(out, "nothing to change") {
		t.Fatalf("no-op mismatch: %s", out)
	}
	t.Logf("[IMP:8][TestUpdateVM][RESULT] tags=2 muted metrics audit=1 noop=ok")
}

func TestCheckTools_CRUDAndSystemRefusal(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, store.VM{Name: "ck", Hostname: "10.0.0.3", PortSSH: 22})
	_ = s.EnsureSystemLiveness(ctx, vmID, 22)
	_ = s.EnsureSystemExposures(ctx, vmID)
	reg := NewRegistry(CheckTools(s)...)

	// add
	out, err := reg.Run(ctx, "add_check", map[string]any{
		"vm_id": float64(vmID), "check_type": "http", "params": map[string]any{"url": "http://10.0.0.3/"},
		"interval_sec": float64(120),
	})
	if err != nil || !strings.Contains(out, `"added":true`) {
		t.Fatalf("add_check: %v %s", err, out)
	}
	// list shows system + new
	out, _ = reg.Run(ctx, "list_checks", map[string]any{"vm_id": float64(vmID)})
	var rows []map[string]any
	_ = json.Unmarshal([]byte(out), &rows)
	if len(rows) != 3 { // liveness + exposures (system) + http
		t.Fatalf("list want 3 checks, got %d (%s)", len(rows), out)
	}
	var httpID, sysID int64
	for _, r := range rows {
		if r["check_type"] == "http" {
			httpID = int64(r["id"].(float64))
		}
		if r["system"] == true {
			sysID = int64(r["id"].(float64))
		}
	}
	// update interval + disable
	out, _ = reg.Run(ctx, "update_check", map[string]any{"check_id": float64(httpID), "interval_sec": float64(300), "enabled": false})
	if !strings.Contains(out, "interval_sec") {
		t.Fatalf("update_check: %s", out)
	}
	// delete system -> refused with JSON error
	out, _ = reg.Run(ctx, "delete_check", map[string]any{"check_id": float64(sysID)})
	if !strings.Contains(out, "error") {
		t.Fatalf("system delete must refuse: %s", out)
	}
	// delete user check -> ok + audit
	out, _ = reg.Run(ctx, "delete_check", map[string]any{"check_id": float64(httpID)})
	if !strings.Contains(out, `"deleted":true`) {
		t.Fatalf("delete_check: %s", out)
	}
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE action IN ('ai_add_check','ai_update_check','ai_delete_check')`).Scan(&n)
	if n != 3 {
		t.Fatalf("audit want 3, got %d", n)
	}
	t.Logf("[IMP:8][TestCheckTools][RESULT] add/list/update/sysrefuse/delete audit=3")
}

func TestCheckTools_RunNowAndRules(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, store.VM{Name: "rn", Hostname: "127.0.0.1", PortSSH: 22})
	_ = s.EnsureSystemLiveness(ctx, vmID, 22)
	reg := NewRegistry(CheckTools(s)...)

	// run_check_now on the liveness check (localhost:22 -> ok or critical, but must return a status).
	var livenessID int64
	rows, _ := s.ListChecks(ctx, &vmID)
	for _, c := range rows {
		if c.CheckType == "liveness" {
			livenessID = c.ID
		}
	}
	out, err := reg.Run(ctx, "run_check_now", map[string]any{"check_id": float64(livenessID)})
	if err != nil || !strings.Contains(out, `"status"`) {
		t.Fatalf("run_check_now: %v %s", err, out)
	}
	// create rule scoped to the VM
	out, _ = reg.Run(ctx, "create_alert_rule", map[string]any{
		"name": "rn down", "vm_id": float64(vmID), "trigger_status": "critical", "severity": "critical",
	})
	if !strings.Contains(out, `"created":true`) {
		t.Fatalf("create_alert_rule: %s", out)
	}
	var ruleID int64
	_ = s.DB.QueryRowContext(ctx, `SELECT id FROM alert_rules WHERE name='rn down'`).Scan(&ruleID)
	// invalid trigger -> validation surfaced
	out, _ = reg.Run(ctx, "create_alert_rule", map[string]any{"name": "x", "trigger_status": "boom", "severity": "critical"})
	if !strings.Contains(out, "invalid rule") {
		t.Fatalf("validation not surfaced: %s", out)
	}
	// delete rule
	out, _ = reg.Run(ctx, "delete_alert_rule", map[string]any{"rule_id": float64(ruleID)})
	if !strings.Contains(out, `"deleted":true`) {
		t.Fatalf("delete_alert_rule: %s", out)
	}
	t.Logf("[IMP:8][TestCheckTools2][RESULT] runnow=status rule=create+delete validation=ok")
}

func TestDomainMutators_UpdateReminders(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	domID, _ := s.CreateDomain(ctx, store.Domain{Name: "rem.example", MonitorTLS: true})
	reg := NewRegistry(DomainMutatorTools(s)...)

	// update_domain by name
	out, err := reg.Run(ctx, "update_domain", map[string]any{"name": "rem.example", "cert_notify_days": float64(14), "monitor_whois": true})
	if err != nil || !strings.Contains(out, `"ok":true`) {
		t.Fatalf("update_domain: %v %s", err, out)
	}
	d, _ := s.GetDomain(ctx, domID)
	if d.CertNotifyDays != 14 || !d.MonitorWhois {
		t.Fatalf("domain update mismatch: %+v", d)
	}
	// add reminder (channel omitted -> in-app only)
	out, _ = reg.Run(ctx, "add_domain_reminder", map[string]any{"name": "rem.example", "kind": "cert", "days": float64(14)})
	if !strings.Contains(out, `"added":true`) {
		t.Fatalf("add reminder: %s", out)
	}
	// list
	out, _ = reg.Run(ctx, "list_domain_reminders", map[string]any{"name": "rem.example"})
	var rems []map[string]any
	_ = json.Unmarshal([]byte(out), &rems)
	if len(rems) != 1 || rems[0]["kind"] != "cert" {
		t.Fatalf("reminders list mismatch: %s", out)
	}
	rid := int64(rems[0]["id"].(float64))
	// bad kind refused
	out, _ = reg.Run(ctx, "add_domain_reminder", map[string]any{"name": "rem.example", "kind": "bogus", "days": float64(5)})
	if !strings.Contains(out, "cert or owner") {
		t.Fatalf("kind validation: %s", out)
	}
	// delete
	out, _ = reg.Run(ctx, "delete_domain_reminder", map[string]any{"reminder_id": float64(rid)})
	if !strings.Contains(out, `"deleted":true`) {
		t.Fatalf("delete reminder: %s", out)
	}
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE action IN ('ai_update_domain','ai_add_reminder','ai_delete_reminder')`).Scan(&n)
	if n != 3 {
		t.Fatalf("audit want 3, got %d", n)
	}
	t.Logf("[IMP:8][TestDomainMutators][RESULT] update rem-list delete audit=3")
}
