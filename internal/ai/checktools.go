// Package ai — checks & alert rules tools: full CRUD parity with the web UI.
//
// region MODULE_CONTRACT [DOMAIN(8): AI,Monitoring; CONCEPT(8): CheckTools; TECH(7): store,monitor]
// @purpose Let the assistant manage WHAT is monitored and WHEN alerts fire — the remaining half
//
//	of the web UI's power: list/add/update/delete checks, run one now, create/delete alert rules.
//	Deletion of easily-recreatable objects (checks, rules) is allowed per operator decision;
//	system-managed checks are refused by the store itself.
//
// @invariants
//   - All mutations audit (ai_add_check / ai_update_check / ai_delete_check / ai_add_alert_rule /
//     ai_delete_alert_rule).
//   - run_check_now executes the REAL check engine and persists the result (same as the UI button).
//   - Rule editing is delete+recreate (parity with the web UI — no UpdateAlertRule exists).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: check tools, list checks, add check, update check, delete check, run now, alert rule, create rule, delete rule
// STRUCTURE: ▶ CRUD: ┌args┐ → ◇ validate/resolve → ⚡ store.X → ⚡ audit → ⎷ JSON ; run_now: ○ GetCheck → ⚡ ExecuteCheck → ⎷ result
package ai

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/skibine/vm-pulse/internal/monitor"
	"github.com/skibine/vm-pulse/internal/store"
)

// CheckTools builds the checks & alert-rules tool set.
func CheckTools(s *store.Store) []Tool {
	tools := []Tool{
		{
			Name: "list_checks",
			Description: "List checks of a VM (vm_id) or domain (domain_id): {id, check_type, " +
				"params, interval_sec, enabled, system}. System checks (auto liveness/exposures) are " +
				"marked and cannot be deleted.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id":     map[string]any{"type": "integer"},
					"domain_id": map[string]any{"type": "integer"},
				},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				if vmID, ok := intArg(args, "vm_id"); ok {
					rows, err := s.ListChecks(ctx, &vmID)
					if err != nil {
						return "", err
					}
					return checksJSON(rows)
				}
				if domID, ok := intArg(args, "domain_id"); ok {
					rows, err := s.ListChecksByDomain(ctx, domID)
					if err != nil {
						return "", err
					}
					return checksJSON(rows)
				}
				return "", fmt.Errorf("vm_id or domain_id required")
			},
		},
		{
			Name: "add_check",
			Description: "Add a monitoring check to a VM or domain: check_type one of tcp/http/ping/" +
				"dns/dnsbl (VM) or whois/tls/dns (domain); params {port,url,host,...}; interval_sec " +
				"default 60. For VMs prefer the system types the UI uses (tcp liveness).",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id":        map[string]any{"type": "integer"},
					"domain_id":    map[string]any{"type": "integer"},
					"check_type":   map[string]any{"type": "string"},
					"params":       map[string]any{"type": "object"},
					"interval_sec": map[string]any{"type": "integer"},
				},
				"required": []string{"check_type"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				ctype, _ := strArg(args, "check_type")
				interval := 60
				if iv, ok := intArg(args, "interval_sec"); ok && iv > 0 {
					interval = int(iv)
				}
				c := store.Check{CheckType: ctype, Params: argMap(args, "params"),
					IntervalSec: interval, Enabled: true}
				if vmID, ok := intArg(args, "vm_id"); ok {
					id := vmID
					c.VMID, c.TargetType = &id, "vm"
				} else if domID, ok := intArg(args, "domain_id"); ok {
					id := domID
					c.DomainID, c.TargetType = &id, "domain"
				} else {
					return "", fmt.Errorf("vm_id or domain_id required")
				}
				id, err := s.CreateCheck(ctx, c)
				if err != nil {
					var ve store.ValidationError
					if asValidation(err, &ve) {
						return jsonStr(map[string]any{"error": "invalid check: " + ve.Error(), "field": ve.Field})
					}
					return "", err
				}
				auditAppendAI(s, "ai_add_check", "check", strconv.FormatInt(id, 10), true)
				return jsonStr(map[string]any{"added": true, "check_id": id, "check_type": ctype, "interval_sec": interval})
			},
		},
		{
			Name: "update_check",
			Description: "Change a check: interval_sec, params, enabled (pause/resume). Only " +
				"provided fields change.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"check_id":     map[string]any{"type": "integer"},
					"interval_sec": map[string]any{"type": "integer"},
					"params":       map[string]any{"type": "object"},
					"enabled":      map[string]any{"type": "boolean"},
				},
				"required": []string{"check_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				checkID, _ := intArg(args, "check_id")
				c, err := s.GetCheck(ctx, checkID)
				if err != nil {
					return jsonStr(map[string]any{"error": "check not found", "check_id": checkID})
				}
				changed := []string{}
				if iv, ok := intArg(args, "interval_sec"); ok && iv > 0 {
					c.IntervalSec = int(iv)
					changed = append(changed, "interval_sec")
				}
				if p := argMap(args, "params"); p != nil {
					c.Params = p
					changed = append(changed, "params")
				}
				if en, ok := args["enabled"].(bool); ok {
					c.Enabled = en
					changed = append(changed, "enabled")
				}
				if len(changed) == 0 {
					return jsonStr(map[string]any{"ok": true, "changed": []string{}})
				}
				if err := s.UpdateCheck(ctx, c); err != nil {
					var ve store.ValidationError
					if asValidation(err, &ve) {
						return jsonStr(map[string]any{"error": "invalid check: " + ve.Error()})
					}
					return "", err
				}
				auditAppendAI(s, "ai_update_check", "check", strconv.FormatInt(checkID, 10), true)
				return jsonStr(map[string]any{"ok": true, "changed": changed})
			},
		},
		{
			Name: "delete_check",
			Description: "Delete a monitoring check (confirm with the user first — it is easily " +
				"recreated via add_check). SYSTEM checks (auto liveness/exposures) are refused.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"check_id": map[string]any{"type": "integer"}},
				"required":   []string{"check_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				checkID, _ := intArg(args, "check_id")
				c, err := s.GetCheck(ctx, checkID)
				if err != nil {
					return jsonStr(map[string]any{"error": "check not found", "check_id": checkID})
				}
				if err := s.DeleteCheck(ctx, checkID); err != nil {
					if errors.Is(err, store.ErrSystemCheck) {
						return jsonStr(map[string]any{"error": err.Error(), "check_id": checkID, "system": c.System})
					}
					if strings.Contains(err.Error(), "not found") {
						return jsonStr(map[string]any{"error": "check not found", "check_id": checkID})
					}
					return "", err
				}
				auditAppendAI(s, "ai_delete_check", "check", strconv.FormatInt(checkID, 10), true)
				return jsonStr(map[string]any{"deleted": true, "check_id": checkID, "check_type": c.CheckType})
			},
		},
		{
			Name: "run_check_now",
			Description: "Execute one check IMMEDIATELY (bypassing the schedule) and return the live " +
				"result — the 'run now' button of the UI. Result is persisted like a scheduled run.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"check_id": map[string]any{"type": "integer"}},
				"required":   []string{"check_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				checkID, _ := intArg(args, "check_id")
				c, err := s.GetCheck(ctx, checkID)
				if err != nil {
					return jsonStr(map[string]any{"error": "check not found", "check_id": checkID})
				}
				res, err := monitor.ExecuteCheck(ctx, s, monitor.DefaultRegistry(), nil, c)
				if err != nil {
					return jsonStr(map[string]any{"error": err.Error()})
				}
				return jsonStr(map[string]any{
					"status": string(res.Status), "latency_ms": res.LatencyMS,
					"message": res.Message, "detail": res.Detail,
				})
			},
		},
		{
			Name: "create_alert_rule",
			Description: "Create an alert rule: fires when checks of check_type (liveness/tcp/http/" +
				"... or '' = any) reach trigger_status (warn|critical|unknown). vm_id scopes the rule " +
				"to one server (omit for fleet-wide); severity warning|critical; cooldown_sec " +
				"re-notification interval (0 = edge-triggered only).",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":           map[string]any{"type": "string"},
					"vm_id":          map[string]any{"type": "integer"},
					"check_type":     map[string]any{"type": "string"},
					"trigger_status": map[string]any{"type": "string"},
					"severity":       map[string]any{"type": "string"},
					"cooldown_sec":   map[string]any{"type": "integer"},
				},
				"required": []string{"name", "trigger_status", "severity"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				name, _ := strArg(args, "name")
				trig, _ := strArg(args, "trigger_status")
				sev, _ := strArg(args, "severity")
				r := store.AlertRule{Name: name, TriggerStatus: trig, Severity: sev, Enabled: true}
				if ct, ok := strArg(args, "check_type"); ok {
					r.CheckType = ct
				}
				if cd, ok := intArg(args, "cooldown_sec"); ok {
					r.CooldownSec = int(cd)
				}
				if vmID, ok := intArg(args, "vm_id"); ok {
					id := vmID
					r.VMID = &id
				}
				id, err := s.CreateAlertRule(ctx, r)
				if err != nil {
					var ve store.ValidationError
					if asValidation(err, &ve) {
						return jsonStr(map[string]any{"error": "invalid rule: " + ve.Error(), "field": ve.Field})
					}
					return "", err
				}
				auditAppendAI(s, "ai_add_alert_rule", "rule", strconv.FormatInt(id, 10), true)
				return jsonStr(map[string]any{"created": true, "rule_id": id})
			},
		},
		{
			Name: "delete_alert_rule",
			Description: "Delete an alert rule (confirm with the user first — recreate via " +
				"create_alert_rule or ensure_liveness_rule). Use list_alert_rules to find the id.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"rule_id": map[string]any{"type": "integer"}},
				"required":   []string{"rule_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				ruleID, _ := intArg(args, "rule_id")
				if err := s.DeleteAlertRule(ctx, ruleID); err != nil {
					return jsonStr(map[string]any{"error": "rule not found or not deletable", "rule_id": ruleID})
				}
				auditAppendAI(s, "ai_delete_alert_rule", "rule", strconv.FormatInt(ruleID, 10), true)
				return jsonStr(map[string]any{"deleted": true, "rule_id": ruleID})
			},
		},
	}
	return tools
}

// checksJSON renders check rows compactly for the model.
func checksJSON(rows []store.Check) (string, error) {
	out := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		entry := map[string]any{
			"id": c.ID, "check_type": c.CheckType, "interval_sec": c.IntervalSec,
			"enabled": c.Enabled, "system": c.System, "params": c.Params,
		}
		if c.VMID != nil {
			entry["vm_id"] = *c.VMID
		}
		if c.DomainID != nil {
			entry["domain_id"] = *c.DomainID
		}
		out = append(out, entry)
	}
	return jsonStr(out)
}
