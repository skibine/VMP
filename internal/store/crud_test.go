// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): CRUD; TECH(8): go test]
// @purpose Verify repository round-trips for VM/Check/Domain: create→get→list→update,
//
//	validation, soft-delete (VM), unique-name (Domain), and JSON field survival.
//	Prints [IMP:7-10] lines (Semantic Trace).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, CRUD, VM, Check, Domain, round-trip, validation, soft-delete, unique
// STRUCTURE: ▶ ┌store┐ → ⊕ Create → ○ Get/List → ⚡ Update/Archive → 〈assert〉 → ⎋ ok
package store

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func openTestStore(t *testing.T) (*Store, *bytes.Buffer) {
	t.Helper()
	log, buf := testLogger(t)
	s, err := Open(filepath.Join(t.TempDir(), "crud.sqlite"), log)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, buf
}

func f64(v float64) *float64 { return &v }
func i64(v int64) *int64     { return &v }

func assertIMP(t *testing.T, buf interface{ String() string }, anchor string) {
	t.Helper()
	out := buf.String()
	if !strings.Contains(out, anchor) {
		t.Errorf("Anti-Illusion: expected Semantic Trace anchor %q in logs, got:\n%s", anchor, out)
	}
}

func TestVM_CRUD_RoundTrip(t *testing.T) {
	s, buf := openTestStore(t)
	ctx := context.Background()

	id, err := s.CreateVM(ctx, VM{
		Name: "web1", Hostname: "10.0.0.1", PortSSH: 22, Tags: []string{"prod", "eu"},
		CostMonthly: f64(5.5), Currency: "USD", AgentEnabled: true,
	})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	got, err := s.GetVM(ctx, id)
	if err != nil {
		t.Fatalf("GetVM: %v", err)
	}
	if len(got.Tags) != 2 || got.Tags[0] != "prod" || got.Tags[1] != "eu" {
		t.Fatalf("tags round-trip failed: %v", got.Tags)
	}
	if got.CostMonthly == nil || *got.CostMonthly != 5.5 {
		t.Fatalf("cost_monthly round-trip failed: %v", got.CostMonthly)
	}
	if !got.AgentEnabled {
		t.Fatal("agent_enabled round-trip failed")
	}

	// List excludes archived.
	list, err := s.ListVMs(ctx, false)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListVMs want 1, got %d (err %v)", len(list), err)
	}

	// Update.
	got.Notes = "primary"
	if err := s.UpdateVM(ctx, got); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	upd, _ := s.GetVM(ctx, id)
	if upd.Notes != "primary" {
		t.Fatalf("update failed: %q", upd.Notes)
	}

	// Archive -> default list empty, archived list has it.
	if err := s.ArchiveVM(ctx, id); err != nil {
		t.Fatalf("ArchiveVM: %v", err)
	}
	if l, _ := s.ListVMs(ctx, false); len(l) != 0 {
		t.Fatalf("archived VM should be hidden from default list, got %d", len(l))
	}
	if l, _ := s.ListVMs(ctx, true); len(l) != 1 {
		t.Fatalf("archived VM should appear with includeArchived, got %d", len(l))
	}

	printIMPFromBuf(t, buf)
	assertIMP(t, buf, "[IMP:8][CreateVM][CREATED]")
}

func TestVM_Validation(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	cases := []VM{
		{Name: "", Hostname: "h", PortSSH: 22}, // empty name
		{Name: "x", Hostname: "", PortSSH: 22}, // empty hostname
		{Name: "x", Hostname: "h", PortSSH: 0}, // bad port
	}
	for i, c := range cases {
		if _, err := s.CreateVM(ctx, c); err == nil {
			t.Errorf("case %d: expected validation error, got nil", i)
		}
	}
}

func TestCheck_CRUD_RoundTrip(t *testing.T) {
	s, buf := openTestStore(t)
	ctx := context.Background()

	vmID, _ := s.CreateVM(ctx, VM{Name: "v", Hostname: "h", PortSSH: 22})
	id, err := s.CreateCheck(ctx, Check{
		VMID: i64(vmID), TargetType: "vm", CheckType: "ping", IntervalSec: 60,
		Params:     map[string]any{"count": 3.0},
		Thresholds: map[string]any{"latency_ms": 100.0},
	})
	if err != nil {
		t.Fatalf("CreateCheck: %v", err)
	}
	got, err := s.GetCheck(ctx, id)
	if err != nil {
		t.Fatalf("GetCheck: %v", err)
	}
	if c, _ := got.Params["count"].(float64); c != 3 {
		t.Fatalf("params round-trip failed: %#v", got.Params)
	}
	if v, _ := got.Thresholds["latency_ms"].(float64); v != 100 {
		t.Fatalf("thresholds round-trip failed: %#v", got.Thresholds)
	}
	// List by vm.
	if l, _ := s.ListChecks(ctx, &vmID); len(l) != 1 {
		t.Fatalf("ListChecks(vm) want 1, got %d", len(l))
	}
	// Delete.
	if err := s.DeleteCheck(ctx, id); err != nil {
		t.Fatalf("DeleteCheck: %v", err)
	}
	if _, err := s.GetCheck(ctx, id); err == nil {
		t.Fatal("GetCheck after delete should fail")
	}
	printIMPFromBuf(t, buf)
	assertIMP(t, buf, "[IMP:8][CreateCheck][CREATED]")
}

func TestCheck_Validation_TargetConsistency(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	// target_type=vm but no vm_id -> validation error.
	if _, err := s.CreateCheck(ctx, Check{TargetType: "vm", CheckType: "ping", IntervalSec: 60}); err == nil {
		t.Fatal("expected validation error for vm check without vm_id")
	}
	// unsupported check_type.
	vmID, _ := s.CreateVM(ctx, VM{Name: "v", Hostname: "h", PortSSH: 22})
	if _, err := s.CreateCheck(ctx, Check{VMID: i64(vmID), TargetType: "vm", CheckType: "magic", IntervalSec: 60}); err == nil {
		t.Fatal("expected validation error for unsupported check_type")
	}
}

func TestDomain_CRUD_AndUnique(t *testing.T) {
	s, buf := openTestStore(t)
	ctx := context.Background()

	id, err := s.CreateDomain(ctx, Domain{Name: "example.com", MonitorTLS: true})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	// Duplicate name.
	if _, err := s.CreateDomain(ctx, Domain{Name: "example.com"}); err != ErrDuplicate {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
	// Empty name validation.
	if _, err := s.CreateDomain(ctx, Domain{Name: "  "}); err == nil {
		t.Fatal("expected validation error for empty domain name")
	}
	got, _ := s.GetDomain(ctx, id)
	if got.Name != "example.com" || !got.MonitorTLS {
		t.Fatalf("domain round-trip failed: %+v", got)
	}
	printIMPFromBuf(t, buf)
	assertIMP(t, buf, "[IMP:8][CreateDomain][CREATED]")
}
