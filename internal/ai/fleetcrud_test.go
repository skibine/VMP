// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): FleetCRUD; TECH(8): go test]
// @purpose Verify the AI fleet CRUD the operator needs for wrong-address incidents:
//
//	update_vm fixes hostname/ip/port_ssh and re-targets the system liveness probe;
//	delete_vm/delete_domain refuse without an explicit confirm; archive_vm keeps history.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, update_vm, ip, port_ssh, liveness retarget, archive_vm, delete_vm, delete_domain, confirm
// STRUCTURE: ▶ ┌store+reg┐ → ⊕ add_vm → ⚡ update ip/port → ○ read liveness params 〈port moved?〉 → ◈delete〈confirm〉 → 〈refused〉
package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/store"
)

// region FUNC_test_FleetCRUD_VM [DOMAIN(7): Testing; CONCEPT(8): WrongAddressFix; TECH(6): Registry]
// @purpose The wrong-IP/wrong-port incident path: agent edits the address and the system liveness
//
//	check follows the new port without recreating anything.
//
// @complexity 5
// endregion FUNC_test_FleetCRUD_VM
func TestFleetCRUD_VMAddressAndLifecycle(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	reg := NewRegistry(append(FleetMutators(s), VMTools(s, nil)...)...)

	out, err := reg.Run(ctx, "add_vm", map[string]any{"name": "nina-vpn", "hostname": "203.0.113.10", "port_ssh": float64(22)})
	if err != nil || !strings.Contains(out, `"added":true`) {
		t.Fatalf("add_vm: %v %s", err, out)
	}

	// Fix the wrong IP via the agent (the incident path).
	out, err = reg.Run(ctx, "update_vm", map[string]any{"vm_id": float64(1), "ip": "198.51.100.7", "hostname": "198.51.100.7"})
	if err != nil || !strings.Contains(out, `"ok":true`) || !strings.Contains(out, "ip") {
		t.Fatalf("update_vm ip: %v %s", err, out)
	}
	vm, _ := s.GetVM(ctx, 1)
	if vm.IP != "198.51.100.7" {
		t.Fatalf("vm.IP not fixed: %+v", vm)
	}

	// Fix the port: the system liveness check must re-target 2222.
	out, err = reg.Run(ctx, "update_vm", map[string]any{"vm_id": float64(1), "port_ssh": float64(2222)})
	if err != nil || !strings.Contains(out, "liveness_port=2222") {
		t.Fatalf("update_vm port: %v %s", err, out)
	}
	checks, _ := s.ListChecks(ctx, nil)
	var live *store.Check
	for i := range checks {
		if checks[i].CheckType == "liveness" {
			live = &checks[i]
		}
	}
	if live == nil {
		t.Fatal("no liveness check found")
	}
	if p, _ := live.Params["port"].(float64); int(p) != 2222 {
		t.Fatalf("liveness probe port must follow to 2222, got %v (params=%+v)", live.Params["port"], live.Params)
	}
	if vm2, _ := s.GetVM(ctx, 1); vm2.PortSSH != 2222 {
		t.Fatalf("vm.PortSSH must be 2222, got %d", vm2.PortSSH)
	}
	t.Logf("[IMP:8][TestFleetCRUD][RESULT] ip fixed + liveness re-targeted to 2222 (check id=%d)", live.ID)

	// delete without confirm -> refused.
	out, _ = reg.Run(ctx, "delete_vm", map[string]any{"vm_id": float64(1)})
	if strings.Contains(out, `"deleted":true`) {
		t.Fatalf("delete_vm must refuse without confirm: %s", out)
	}
	if !strings.Contains(out, "confirmation required") {
		t.Fatalf("delete_vm refusal must explain confirm: %s", out)
	}
	// archive keeps the row (archived), delete with confirm wipes it.
	out, _ = reg.Run(ctx, "archive_vm", map[string]any{"vm_id": float64(1)})
	if !strings.Contains(out, `"archived":true`) {
		t.Fatalf("archive_vm: %s", out)
	}
	out, _ = reg.Run(ctx, "delete_vm", map[string]any{"vm_id": float64(1), "confirm": "yes"})
	if !strings.Contains(out, `"deleted":true`) {
		t.Fatalf("delete_vm confirm path: %s", out)
	}
	if _, err := s.GetVM(ctx, 1); err == nil {
		t.Fatal("vm must be gone after confirmed delete")
	}
	t.Logf("[IMP:9][TestFleetCRUD][RESULT] delete_vm confirm-gate ok, vm wiped")
}

// region FUNC_test_FleetCRUD_Domain [DOMAIN(7): Testing; CONCEPT(7): DomainRenameDelete; TECH(6): Registry]
// @purpose Rename fixes a domain typo in place; delete_domain refuses without confirm.
// @complexity 3
// endregion FUNC_test_FleetCRUD_Domain
func TestFleetCRUD_DomainRenameAndDelete(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	reg := NewRegistry(DomainMutatorTools(s)...)

	if _, err := s.CreateDomain(ctx, store.Domain{Name: "exmaple.pro", MonitorTLS: true}); err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}

	// The typo fix: rename by domain_id + name.
	out, err := reg.Run(ctx, "update_domain", map[string]any{"domain_id": float64(1), "name": "example.pro"})
	if err != nil || !strings.Contains(out, "name") {
		t.Fatalf("update_domain rename: %v %s", err, out)
	}
	d, _ := s.GetDomain(ctx, 1)
	if d.Name != "example.pro" {
		t.Fatalf("domain rename failed, got %q", d.Name)
	}
	t.Logf("[IMP:8][TestFleetCRUD][RESULT] domain renamed to %s", d.Name)

	out, _ = reg.Run(ctx, "delete_domain", map[string]any{"domain_id": float64(1)})
	if strings.Contains(out, `"deleted":true`) || !strings.Contains(out, "confirmation required") {
		t.Fatalf("delete_domain must refuse without confirm: %s", out)
	}
	out, _ = reg.Run(ctx, "delete_domain", map[string]any{"domain_id": float64(1), "confirm": "yes"})
	if !strings.Contains(out, `"deleted":true`) {
		t.Fatalf("delete_domain confirm path: %s", out)
	}
	if _, err := s.GetDomain(ctx, 1); err == nil {
		t.Fatal("domain must be gone after confirmed delete")
	}
}

// region FUNC_test_Store_EnsureSystemLiveness_PortSync [DOMAIN(7): Testing; CONCEPT(7): LivenessPort; TECH(6): store]
// @purpose Store-level invariant: EnsureSystemLiveness updates the port of the EXISTING liveness
//
//	check (and no longer treats a lone exposures check as liveness-present).
//
// @complexity 3
// endregion FUNC_test_Store_EnsureSystemLiveness_PortSync
func TestStore_EnsureSystemLiveness_PortSync(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	vmID, err := s.CreateVM(ctx, store.VM{Name: "v", Hostname: "h", PortSSH: 22})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if err := s.EnsureSystemLiveness(ctx, vmID, 22); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := s.EnsureSystemLiveness(ctx, vmID, 2202); err != nil {
		t.Fatalf("ensure 2202: %v", err)
	}
	checks, _ := s.ListChecks(ctx, nil)
	n := 0
	port := 0
	for _, c := range checks {
		if c.CheckType == "liveness" {
			n++
			if f, ok := c.Params["port"].(float64); ok {
				port = int(f)
			}
		}
	}
	if n != 1 || port != 2202 {
		t.Fatalf("want exactly 1 liveness check on port 2202, got n=%d port=%d", n, port)
	}
	// Idempotent second call keeps one check.
	_ = s.EnsureSystemLiveness(ctx, vmID, 2202)
	checks2, _ := s.ListChecks(ctx, nil)
	n2 := 0
	for _, c := range checks2 {
		if c.CheckType == "liveness" {
			n2++
		}
	}
	if n2 != 1 {
		t.Fatalf("liveness must stay single, got %d", n2)
	}
	t.Logf("[IMP:8][TestLivenessPort][RESULT] single liveness check, port=%d", port)
}

// endregion FUNC_test_Store_EnsureSystemLiveness_PortSync
