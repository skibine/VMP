// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): AlertTools; TECH(8): go test]
// @purpose Verify the alert-config tools: channel resolve by name/id/unknown, coverage logic
//
//	(scoped / fleet-wide / muted), rule creation, no secrets in list_channels, audit entries.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, alert tools, set_vm_alert_channels, ensure_liveness_rule, channels, coverage
// STRUCTURE: ▶ ┌store+channels+vm┐ → ○ tool.Run → 〈resolve/cover?〉 → ⎋ assert
package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/store"
)

func TestListChannels_NoSecrets(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	if _, err := s.CreateChannel(ctx, store.Channel{Type: "telegram", Name: "VM-Pulse", Enabled: true,
		Config: map[string]any{"bot_token": "123:SECRET", "chat_id": "42"}}); err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}
	out, err := NewRegistry(AlertTools(s)...).Run(ctx, "list_channels", nil)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out, "SECRET") || strings.Contains(out, "bot_token") || strings.Contains(out, "chat_id") {
		t.Fatalf("secret leaked into list_channels: %s", out)
	}
	var list []map[string]any
	_ = json.Unmarshal([]byte(out), &list)
	// The seeded in-app channel + the one created here.
	if len(list) != 2 {
		t.Fatalf("want 2 channels (seeded bell + telegram), got %s", out)
	}
	for _, c := range list {
		if c["name"] == "VM-Pulse" && c["type"] == "telegram" {
			t.Logf("[IMP:8][TestListChannels][RESULT] channels=%d secrets=none", len(list))
			return
		}
	}
	t.Fatalf("telegram channel missing: %s", out)
}

func TestSetVMAlertChannels_ByNameIdUnknown(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	tgID, _ := s.CreateChannel(ctx, store.Channel{Type: "telegram", Name: "VM-Pulse", Enabled: true})
	bellID, _ := s.CreateChannel(ctx, store.Channel{Type: "in-app", Name: "in-app (bell)", Enabled: true})
	vmID, _ := s.CreateVM(ctx, store.VM{Name: "Kate", Hostname: "k.example", PortSSH: 22})
	reg := NewRegistry(AlertTools(s)...)

	// By name AND id mixed, with a duplicate.
	out, err := reg.Run(ctx, "set_vm_alert_channels", map[string]any{
		"vm_id": float64(vmID), "channels": []any{"VM-Pulse", "in-app (bell)", float64(tgID)},
	})
	if err != nil {
		t.Fatalf("set: %v", err)
	}
	if !strings.Contains(out, `"ok":true`) {
		t.Fatalf("want ok, got %s", out)
	}
	attached, _ := s.ListVMChannels(ctx, vmID)
	if len(attached) != 2 { // dedup worked
		t.Fatalf("want 2 attached channels, got %d", len(attached))
	}
	var auditN int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE action='ai_set_vm_channels'`).Scan(&auditN)
	if auditN != 1 {
		t.Fatalf("want 1 audit row, got %d", auditN)
	}

	// Unknown name -> JSON error with the available list.
	out, err = reg.Run(ctx, "set_vm_alert_channels", map[string]any{
		"vm_id": float64(vmID), "channels": []any{"nope"},
	})
	if err != nil {
		t.Fatalf("unknown must be a JSON payload, got err %v", err)
	}
	if !strings.Contains(out, "unknown channel") || !strings.Contains(out, "VM-Pulse") {
		t.Fatalf("unknown-channel payload mismatch: %s", out)
	}
	// Still the old attachment (unchanged on error).
	attached, _ = s.ListVMChannels(ctx, vmID)
	if len(attached) != 2 {
		t.Fatalf("attachment must be untouched on unknown, got %d", len(attached))
	}

	// Empty list detaches all.
	if _, err := reg.Run(ctx, "set_vm_alert_channels", map[string]any{
		"vm_id": float64(vmID), "channels": []any{},
	}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	attached, _ = s.ListVMChannels(ctx, vmID)
	if len(attached) != 0 {
		t.Fatalf("detach failed, got %d", len(attached))
	}
	_ = bellID
	t.Logf("[IMP:9][TestSetVMChannels][RESULT] attach=2 dedup audit=1 unknown=available detach=0")
}

func TestEnsureLivenessRule_Coverage(t *testing.T) {
	s := newToolsStore(t)
	ctx := context.Background()
	kate, _ := s.CreateVM(ctx, store.VM{Name: "Kate", Hostname: "k.example", PortSSH: 22})
	reg := NewRegistry(AlertTools(s)...)

	// No rules at all -> create scoped.
	out, _ := reg.Run(ctx, "ensure_liveness_rule", map[string]any{"vm_id": float64(kate)})
	if !strings.Contains(out, `"created":true`) {
		t.Fatalf("want created=true, got %s", out)
	}
	rules, _ := s.ListAlertRules(ctx)
	if len(rules) != 1 || rules[0].VMID == nil || *rules[0].VMID != kate || rules[0].CheckType != "liveness" {
		t.Fatalf("scoped rule not created: %+v", rules)
	}
	createdID := rules[0].ID

	// Second call: covered by the scoped rule -> no new rule.
	out, _ = reg.Run(ctx, "ensure_liveness_rule", map[string]any{"vm_id": float64(kate)})
	if !strings.Contains(out, `"created":false`) || !strings.Contains(out, `"covered":true`) {
		t.Fatalf("want covered/no-create, got %s", out)
	}
	rules, _ = s.ListAlertRules(ctx)
	if len(rules) != 1 {
		t.Fatalf("rule duplicated: %d", len(rules))
	}

	// Fleet-wide enabled rule covers an UNMUTED vm without creating anything.
	other, _ := s.CreateVM(ctx, store.VM{Name: "Other", Hostname: "o.example", PortSSH: 22})
	fleet, _ := s.CreateAlertRule(ctx, store.AlertRule{Name: "any down", CheckType: "liveness",
		TriggerStatus: "critical", Severity: "critical", Enabled: true})
	out, _ = reg.Run(ctx, "ensure_liveness_rule", map[string]any{"vm_id": float64(other)})
	if !strings.Contains(out, `"rule_id":`) || strings.Contains(out, `"created":true`) {
		t.Fatalf("fleet-wide must cover, got %s", out)
	}

	// But a MUTED vm is NOT covered by fleet-wide -> scoped rule is created.
	if err := s.SetAlertMute(ctx, other, true); err != nil {
		t.Fatalf("mute: %v", err)
	}
	out, _ = reg.Run(ctx, "ensure_liveness_rule", map[string]any{"vm_id": float64(other)})
	if !strings.Contains(out, `"created":true`) {
		t.Fatalf("muted vm must get its own rule, got %s", out)
	}
	rules, _ = s.ListAlertRules(ctx)
	if len(rules) != 3 { // kate-scoped + fleet-wide + muted-other-scoped
		t.Fatalf("want 3 rules after muted-vm ensure, got %d", len(rules))
	}
	var auditN int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM audit_log WHERE action='ai_add_alert_rule'`).Scan(&auditN)
	if auditN != 2 { // kate + muted other
		t.Fatalf("want 2 audit rows, got %d", auditN)
	}
	_ = createdID
	_ = fleet
	t.Logf("[IMP:9][TestEnsureRule][RESULT] scoped=1 idempotent fleet=muted-own-rule audit=2")
}
