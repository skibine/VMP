// Package ai — alert-configuration tools: let the assistant SET UP alerting for a VM.
//
// region MODULE_CONTRACT [DOMAIN(8): AI,Alerting; CONCEPT(8): AlertTools; TECH(7): store,audit]
// @purpose Let the assistant fulfill "поставь оповещения на <vm>" end-to-end. The delivery model
//
//	is per-server routing: a VM's alerts go to ITS attached channels when a covering rule fires.
//	So the assistant needs exactly two mutations — attach channels to the VM
//	(set_vm_alert_channels) and make sure a liveness rule COVERS the VM (ensure_liveness_rule) —
//	plus two reads (list_channels, list_alert_rules) to see what exists.
//
// @invariants
//   - list_channels NEVER returns channel configs (bot_token/webhook secret stay server-side).
//   - Mutations execute immediately (low-risk config, Plane A) and land in the audit chain
//     (ai_set_vm_channels / ai_add_alert_rule) — same policy as add_vm/add_domain.
//   - ensure_liveness_rule only CREATES a scoped rule when nothing covers the VM; it never
//     edits or deletes existing rules (that stays a web-UI operation).
//
// @rationale
// Q: Why does coverage check consider mutes?
// A: A fleet-wide (vm_id=nil) enabled rule does NOT fire for a muted VM (evaluator skips muted
//    VMs in fleet-wide scope), so "global rule exists" is not enough — the VM must be unmuted or
//    have its own scoped rule. Scoped rules always fire, mute only dampens fleet-wide ones.
// endregion MODULE_CONTRACT
// GREP_SUMMARY: alert tools, set_vm_alert_channels, ensure_liveness_rule, list_channels, list_alert_rules, notifications setup, ai
// STRUCTURE: ▶ set_vm_alert_channels: ┌vm+names/ids┐ → ◇ resolve channels → ⚡ SetVMChannels → ⚡ audit → ⎷ JSON ; ensure_liveness_rule: ┌vm┐ → 〈covered?〉 → ⚡ CreateAlertRule → ⚡ audit → ⎷ JSON
package ai

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/skibine/vm-pulse/internal/store"
)

// AlertTools builds the alerting read/config tools.
func AlertTools(s *store.Store) []Tool {
	return []Tool{
		{
			Name: "list_channels",
			Description: "List the delivery channels (id, name, type, enabled) available for alert " +
				"routing — e.g. a telegram channel or the in-app bell. Channel configs/secrets are " +
				"never included. Use the ids/names in set_vm_alert_channels.",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{}},
			Run: func(ctx context.Context, _ map[string]any) (string, error) {
				chs, err := s.ListChannels(ctx)
				if err != nil {
					return "", err
				}
				out := make([]map[string]any, 0, len(chs))
				for _, c := range chs {
					out = append(out, map[string]any{
						"id": c.ID, "name": c.Name, "type": c.Type, "enabled": c.Enabled,
					})
				}
				return jsonStr(out)
			},
		},
		{
			Name: "list_alert_rules",
			Description: "List alert rules: {id, name, vm_id (null = fleet-wide), check_type, " +
				"trigger_status, severity, enabled}. A VM is COVERED by an enabled rule when the " +
				"rule is fleet-wide (vm_id null, and the VM is not muted) or scoped to that vm_id.",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{}},
			Run: func(ctx context.Context, _ map[string]any) (string, error) {
				rules, err := s.ListAlertRules(ctx)
				if err != nil {
					return "", err
				}
				out := make([]map[string]any, 0, len(rules))
				for _, r := range rules {
					entry := map[string]any{
						"id": r.ID, "name": r.Name, "check_type": r.CheckType,
						"trigger_status": r.TriggerStatus, "severity": r.Severity, "enabled": r.Enabled,
					}
					if r.VMID != nil {
						entry["vm_id"] = *r.VMID
					}
					out = append(out, entry)
				}
				return jsonStr(out)
			},
		},
		{
			Name: "set_vm_alert_channels",
			Description: "Attach delivery channels to a server — its alerts (liveness down/" +
				"recovered etc.) are delivered to exactly these channels. `channels` is the FULL " +
				"replacement set: each element is a channel NAME or numeric id (see list_channels); " +
				"an empty array detaches all. To set up alerts for a VM also call " +
				"ensure_liveness_rule so a rule covers it.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id":    map[string]any{"type": "integer"},
					"channels": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
				},
				"required": []string{"vm_id", "channels"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, ok := intArg(args, "vm_id")
				if !ok {
					return "", fmt.Errorf("vm_id required")
				}
				if _, err := s.GetVM(ctx, vmID); err != nil {
					return jsonStr(map[string]any{"error": "vm not found", "vm_id": vmID})
				}
				names, _ := args["channels"].([]any)
				all, err := s.ListChannels(ctx)
				if err != nil {
					return "", err
				}
				byName := map[string]int64{}
				for _, c := range all {
					byName[strings.ToLower(c.Name)] = c.ID
				}
				ids := make([]int64, 0, len(names))
				var unknown []string
				for _, raw := range names {
					spec := strings.TrimSpace(fmt.Sprintf("%v", raw))
					id := int64(0)
					if n, err := strconv.ParseInt(spec, 10, 64); err == nil {
						for _, c := range all {
							if c.ID == n {
								id = n
							}
						}
					} else {
						id = byName[strings.ToLower(spec)]
					}
					if id == 0 {
						unknown = append(unknown, spec)
						continue
					}
					dup := false
					for _, x := range ids {
						if x == id {
							dup = true
						}
					}
					if !dup {
						ids = append(ids, id)
					}
				}
				if len(unknown) > 0 {
					avail := make([]string, 0, len(all))
					for _, c := range all {
						avail = append(avail, c.Name)
					}
					return jsonStr(map[string]any{
						"error": "unknown channel(s): " + strings.Join(unknown, ", "),
						"available": avail,
					})
				}
				if err := s.SetVMChannels(ctx, vmID, ids); err != nil {
					return "", err
				}
				auditAppendAI(s, "ai_set_vm_channels", "vm", strconv.FormatInt(vmID, 10), true)
				attached := make([]string, 0, len(ids))
				for _, id := range ids {
					for _, c := range all {
						if c.ID == id {
							attached = append(attached, c.Name)
						}
					}
				}
				return jsonStr(map[string]any{"ok": true, "vm_id": vmID, "channels": attached})
			},
		},
		{
			Name: "ensure_liveness_rule",
			Description: "Make sure a liveness (server down/recovered) rule COVERS the VM: if some " +
				"enabled rule already covers it (fleet-wide + the VM is not muted, or scoped to it), " +
				"return covered=true; otherwise create a scoped critical liveness rule for it. This " +
				"is the second half (besides set_vm_alert_channels) of 'set up alerts for this VM'.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"vm_id": map[string]any{"type": "integer"}},
				"required":   []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, ok := intArg(args, "vm_id")
				if !ok {
					return "", fmt.Errorf("vm_id required")
				}
				vm, err := s.GetVM(ctx, vmID)
				if err != nil {
					return jsonStr(map[string]any{"error": "vm not found", "vm_id": vmID})
				}
				rules, err := s.ListAlertRules(ctx)
				if err != nil {
					return "", err
				}
				muted, _ := s.MutedVMIDs(ctx)
				for _, r := range rules {
					if !r.Enabled || r.CheckType != "liveness" {
						continue
					}
					if r.VMID != nil && *r.VMID == vmID {
						return jsonStr(map[string]any{"covered": true, "rule_id": r.ID, "created": false})
					}
					if r.VMID == nil && !muted[vmID] {
						return jsonStr(map[string]any{"covered": true, "rule_id": r.ID, "created": false})
					}
				}
				ruleID, err := s.CreateAlertRule(ctx, store.AlertRule{
					Name: vm.Name + " down", VMID: &vmID, CheckType: "liveness",
					TriggerStatus: "critical", Severity: "critical", Enabled: true,
				})
				if err != nil {
					var ve store.ValidationError
					if asValidation(err, &ve) {
						return jsonStr(map[string]any{"error": "invalid rule: " + ve.Error()})
					}
					return "", err
				}
				auditAppendAI(s, "ai_add_alert_rule", "vm", strconv.FormatInt(vmID, 10), true)
				return jsonStr(map[string]any{"covered": true, "rule_id": ruleID, "created": true})
			},
		},
	}
}

// asValidation mirrors errors.As for the VALUE-receiver store.ValidationError.
func asValidation(err error, target *store.ValidationError) bool {
	for err != nil {
		if ve, ok := err.(store.ValidationError); ok {
			*target = ve
			return true
		}
		u, isUnwrap := err.(interface{ Unwrap() error })
		if !isUnwrap {
			return false
		}
		err = u.Unwrap()
	}
	return false
}

// compile-time: audit IS used via auditAppendAI (fleettools.go, same package).
