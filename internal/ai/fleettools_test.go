// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): DomainTools,FleetMutators; TECH(8): go test]
// @purpose Verify the domain read tools (stored list + live probe arg handling) and the fleet
//
//	mutators (add_vm/add_domain end-to-end against a tempdir store, incl. audit entries).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, list_domains, get_domain_info, add_vm, add_domain, tools, audit
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// newToolsStore opens a tempdir store with an LDD-capturing logger.
func newToolsStore(t *testing.T) *store.Store {
	t.Helper()
	var buf bytes.Buffer
	logger := logging.Setup(slog.LevelDebug, &buf)
	s, err := store.Open(filepath.Join(t.TempDir(), "tools.sqlite"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		_ = s.Close()
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.Contains(line, "[IMP:7]") || strings.Contains(line, "[IMP:8]") || strings.Contains(line, "[IMP:9]") || strings.Contains(line, "[IMP:10]") {
				t.Log(line)
			}
		}
	})
	return s
}

func TestListDomains_ReportsStoredChecks(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	domID, err := s.CreateDomain(ctx, store.Domain{Name: "example.pro", Registrar: "Tucows"})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if err := s.EnsureDomainChecks(ctx, domID); err != nil {
		t.Fatalf("EnsureDomainChecks: %v", err)
	}
	// Give the whois check a stored result with days remaining in the message.
	rows0, _ := s.ListChecks(ctx, nil)
	for _, c := range rows0 {
		if c.DomainID != nil && *c.DomainID == domID && c.CheckType == "whois" {
			_, _ = s.InsertCheckResult(ctx, c.ID, "ok", 2.0, "registration expires in 15 days", nil)
		}
	}

	tools := DomainTools(s)
	reg := NewRegistry(tools...)
	out, err := reg.Run(ctx, "list_domains", map[string]any{})
	if err != nil {
		t.Fatalf("list_domains: %v", err)
	}
	var list []map[string]any
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatalf("unmarshal: %v (out=%s)", err, out)
	}
	if len(list) != 1 || list[0]["name"] != "example.pro" {
		t.Fatalf("want example.pro, got %s", out)
	}
	checks := list[0]["checks"].(map[string]any)
	whois := checks["whois"].(map[string]any)
	if whois["message"] != "registration expires in 15 days" {
		t.Fatalf("whois stored message mismatch: %+v", whois)
	}
	t.Logf("[IMP:8][TestListDomains][RESULT] domain=%s checks=%d whois_msg=%v", list[0]["name"], len(checks), whois["message"])
}

func TestGetDomainInfo_ArgValidation(t *testing.T) {
	s := newToolsStore(t)
	reg := NewRegistry(DomainTools(s)...)

	// Neither id nor name -> argument error (returned to the agent as tool error).
	if _, err := reg.Run(context.Background(), "get_domain_info", map[string]any{}); err == nil {
		t.Fatalf("want arg error for empty call, got nil")
	}
	// Unknown id -> JSON error payload, not a Go error.
	out, err := reg.Run(context.Background(), "get_domain_info", map[string]any{"domain_id": float64(999)})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if !strings.Contains(out, "domain not found") {
		t.Fatalf("want 'domain not found' payload, got %s", out)
	}
	t.Logf("[IMP:8][TestGetDomainInfo][ARGS] unknown-id payload ok")
}

func TestAddVM_CreatesAndProvisions(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	reg := NewRegistry(FleetMutators(s)...)

	out, err := reg.Run(ctx, "add_vm", map[string]any{"name": "Kate-USA", "hostname": "203.0.113.7"})
	if err != nil {
		t.Fatalf("add_vm: %v", err)
	}
	if !strings.Contains(out, `"added":true`) {
		t.Fatalf("want added:true, got %s", out)
	}
	vms, _ := s.ListVMs(ctx, false)
	if len(vms) != 1 || vms[0].Name != "Kate-USA" || vms[0].IP != "203.0.113.7" || vms[0].PortSSH != 22 {
		t.Fatalf("vm mismatch: %+v", vms)
	}
	// System checks provisioned (liveness + exposures).
	rows, _ := s.LatestResultsForVM(ctx, vms[0].ID)
	types := map[string]bool{}
	for _, r := range rows {
		types[r.CheckType] = true
	}
	if !types["liveness"] || !types["exposures"] {
		t.Fatalf("system checks not provisioned: %v", types)
	}
	// Audit entry written.
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE action='ai_add_vm'`).Scan(&n)
	if n != 1 {
		t.Fatalf("want 1 ai_add_vm audit row, got %d", n)
	}
	t.Logf("[IMP:9][TestAddVM][RESULT] vm=%s id=%d checks=%v audit=1", vms[0].Name, vms[0].ID, types)
}

func TestAddVM_ValidationSurfaced(t *testing.T) {
	s := newToolsStore(t)
	reg := NewRegistry(FleetMutators(s)...)
	out, err := reg.Run(context.Background(), "add_vm", map[string]any{"name": "x"}) // no hostname
	if err != nil {
		t.Fatalf("add_vm should return JSON error payload, got err: %v", err)
	}
	if !strings.Contains(out, "hostname") {
		t.Fatalf("want hostname validation error, got %s", out)
	}
	t.Logf("[IMP:8][TestAddVM][VALIDATE] payload=%s", out)
}

func TestAddVM_KindEquipment(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	reg := NewRegistry(FleetMutators(s)...)

	// Equipment kind flows through.
	out, err := reg.Run(ctx, "add_vm", map[string]any{
		"name": "Keenetic", "hostname": "203.0.113.99", "kind": "equipment",
	})
	if err != nil || !strings.Contains(out, `"added":true`) {
		t.Fatalf("add_vm equipment: %v %s", err, out)
	}
	vms, _ := s.ListVMs(ctx, false)
	if len(vms) != 1 || vms[0].Kind != "equipment" {
		t.Fatalf("kind want equipment: %+v", vms)
	}
	t.Logf("[IMP:8][TestAddVMKind][RESULT] kind=equipment saved")
}

func TestAddDomain_IPGuard(t *testing.T) {
	s := newToolsStore(t)
	reg := NewRegistry(FleetMutators(s)...)

	out, err := reg.Run(context.Background(), "add_domain", map[string]any{"name": "203.0.113.99"})
	if err != nil {
		t.Fatalf("IP guard must be a JSON payload, got err: %v", err)
	}
	if !strings.Contains(out, "not a domain") || !strings.Contains(out, "kind=equipment") {
		t.Fatalf("guard hint mismatch: %s", out)
	}
	// Nothing was created.
	doms, _ := s.ListDomains(context.Background())
	if len(doms) != 0 {
		t.Fatalf("IP must not be stored as domain")
	}
	t.Logf("[IMP:9][TestAddDomainIP][RESULT] refused with add_vm hint, no row created")
}

func TestAddDomain_DuplicateAndFresh(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	reg := NewRegistry(FleetMutators(s)...)

	if _, err := reg.Run(ctx, "add_domain", map[string]any{"name": "Example.pro"}); err != nil {
		t.Fatalf("add_domain fresh: %v", err)
	}
	if _, err := reg.Run(ctx, "add_domain", map[string]any{"name": "example.pro"}); err != nil {
		t.Fatalf("add_domain duplicate: %v", err)
	}
	// Second call must report already-monitored, not create a row.
	doms, _ := s.ListDomains(ctx)
	if len(doms) != 1 {
		t.Fatalf("want exactly 1 domain (dup rejected), got %d", len(doms))
	}
	rows, _ := s.LatestResultsForDomain(ctx, doms[0].ID)
	types := map[string]bool{}
	for _, r := range rows {
		types[r.CheckType] = true
	}
	if !types["whois"] || !types["tls"] {
		t.Fatalf("domain system checks not provisioned: %v", types)
	}
	t.Logf("[IMP:9][TestAddDomain][RESULT] domain=%s checks=%v", doms[0].Name, types)
}
