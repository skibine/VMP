// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: Tools; TECH(8]: go test]
// @purpose Verify the read-only tools return correct JSON from a real store.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, tools, list_vms, get_vm_health, list_alerts, read-only, store
// STRUCTURE: ▶ ┌store+VM+check+result┐ → ○ tool.Run → 〈json?〉 → ⎋ assert
package ai

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"

	"bytes"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
	"log/slog"
)

func newAIStore(t *testing.T) *store.Store {
	t.Helper()
	var buf bytes.Buffer
	logger := logging.Setup(slog.LevelDebug, &buf)
	s, err := store.Open(filepath.Join(t.TempDir(), "ai.sqlite"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStoreTools_listVmsAndHealth(t *testing.T) {
	s := newAIStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, store.VM{Name: "web1", Hostname: "10.0.0.1", IP: "10.0.0.1", PortSSH: 22, Tags: []string{"prod"}})
	chkID, _ := s.CreateCheck(ctx, store.Check{VMID: &vmID, TargetType: "vm", CheckType: "tcp", IntervalSec: 60, Enabled: true})
	_, _ = s.InsertCheckResult(ctx, chkID, "ok", 5.0, "connected", nil)

	reg := NewRegistry(StoreTools(s)...)

	out, err := reg.Run(ctx, "list_vms", nil)
	if err != nil {
		t.Fatalf("list_vms: %v", err)
	}
	var vms []map[string]any
	if err := json.Unmarshal([]byte(out), &vms); err != nil || len(vms) != 1 || vms[0]["name"] != "web1" {
		t.Fatalf("list_vms bad output: %s", out)
	}

	out, err = reg.Run(ctx, "get_vm_health", map[string]any{"vm_id": float64(vmID)})
	if err != nil {
		t.Fatalf("get_vm_health: %v", err)
	}
	var hs map[string]any
	if err := json.Unmarshal([]byte(out), &hs); err != nil || hs["status"] != "ok" {
		t.Fatalf("get_vm_health bad output: %s", out)
	}

	// Unknown tool.
	if _, err := reg.Run(ctx, "nope", nil); err == nil {
		t.Fatal("expected error for unknown tool")
	}
}

func TestStoreTools_listAlerts(t *testing.T) {
	s := newAIStore(t)
	ctx := context.Background()
	rid, _ := s.CreateAlertRule(ctx, store.AlertRule{Name: "r", TriggerStatus: "critical", Severity: "critical", CooldownSec: 60, Enabled: true})
	_, _ = s.InsertAlert(ctx, store.Alert{RuleID: rid, CheckID: 1, Severity: "critical", Message: "down"})

	reg := NewRegistry(StoreTools(s)...)
	out, err := reg.Run(ctx, "list_alerts", nil)
	if err != nil {
		t.Fatalf("list_alerts: %v", err)
	}
	var arr []map[string]any
	if err := json.Unmarshal([]byte(out), &arr); err != nil || len(arr) != 1 {
		t.Fatalf("list_alerts bad output: %s", out)
	}
}
