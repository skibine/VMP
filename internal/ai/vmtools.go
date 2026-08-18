// Package ai — VM diagnostics & config tools: close the capability gap with the web UI.
//
// region MODULE_CONTRACT [DOMAIN(8): AI,Observability; CONCEPT(8): VMTools; TECH(7): monitor,store,ssh]
// @purpose Give the assistant the same VM powers the web UI has: Plane A probes (diagnose,
//
//	port scan, exposure scan, site info), stored metrics, ai-gated SSH readers (snapshot,
//	errors, updates, inventory refresh, vhosts) and config edits (update_vm with mute/metrics
//	folds). Everything the UI can do to a VM, the assistant can now be asked to do.
//
// @invariants
//   - Plane A probes need no credentials and are NOT ai-gated (same as the UI).
//   - SSH readers require the VM's ai_access AND stored credentials (Plane B data path).
//   - update_vm edits metadata/folds only; credentials/ai-access/terminal remain web-only.
//   - Every mutation lands in the audit chain (ai_update_vm).
//
// @rationale
// Q: Why a VMDataReader interface instead of importing ssh directly?
// A: The ai package must not import ssh (import cycle prevention, same pattern as ActionExecutor).
//
//	main.go wires the dialer-backed implementation.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: vm tools, diagnose, deep scan, exposures, site info, snapshot, errors, updates, inventory, vhosts, metrics, update_vm, mute
// STRUCTURE: ▶ probes: ┌vm┐ → ⚡ monitor.* → ⎷ JSON ; ssh: ◇ ai_access? → ⚡ reader.X → ⎷ JSON ; update: ┌fields┐ → ○ merge → ⚡ UpdateVM → ⚡ audit → ⎷
package ai

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/skibine/vm-pulse/internal/monitor"
	"github.com/skibine/vm-pulse/internal/store"
)

// VMDataReader exposes the dialer-backed SSH reads (implemented in main.go over the ssh dialer).
// Returns any so the ssh package's JSON-tagged structs flow straight into tool output.
type VMDataReader interface {
	Snapshot(ctx context.Context, vmID int64) (any, error)
	Errors(ctx context.Context, vmID int64, window string) (any, error)
	Updates(ctx context.Context, vmID int64) (any, error)
	InventoryRefresh(ctx context.Context, vmID int64) (any, error)
	VHosts(ctx context.Context, vmID int64) (any, error)
}

// VMTools builds the VM diagnostics + config tool set.
func VMTools(s *store.Store, reader VMDataReader) []Tool {
	requireAIAccess := func(ctx context.Context, vmID int64) (store.VM, error) {
		vm, err := s.GetVM(ctx, vmID)
		if err != nil {
			return vm, fmt.Errorf("vm not found: %d", vmID)
		}
		if !vm.AIEnabled {
			return vm, fmt.Errorf("ai access disabled for vm %s (enable it in the web UI)", vm.Name)
		}
		return vm, nil
	}
	sshRead := func(ctx context.Context, vmID int64, fn func() (any, error)) (string, error) {
		if _, err := requireAIAccess(ctx, vmID); err != nil {
			return jsonStr(map[string]any{"error": err.Error(), "vm_id": vmID})
		}
		if reader == nil {
			return jsonStr(map[string]any{"error": "ssh reader not wired"})
		}
		out, err := fn()
		if err != nil {
			return jsonStr(map[string]any{"error": err.Error(), "vm_id": vmID})
		}
		return jsonStr(out)
	}
	vmTarget := func(ctx context.Context, vmID int64) (store.VM, string, error) {
		vm, err := s.GetVM(ctx, vmID)
		if err != nil {
			return vm, "", fmt.Errorf("vm not found: %d", vmID)
		}
		host := vm.IP
		if host == "" {
			host = vm.Hostname
		}
		return vm, host, nil
	}

	tools := []Tool{
		{
			Name: "diagnose_vm",
			Description: "Run an ad-hoc probe against a VM from the VM Pulse host (NO credentials " +
				"needed): check_type one of tcp/http/ping/dns/tls/whois/dnsbl (params: port for tcp, " +
				"url for http, host for dns...). This is the 'check now' the UI's diagnose button does.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id":      map[string]any{"type": "integer"},
					"check_type": map[string]any{"type": "string"},
					"params":     map[string]any{"type": "object"},
				},
				"required": []string{"vm_id", "check_type"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				ctype, _ := strArg(args, "check_type")
				vm, _, err := vmTarget(ctx, vmID)
				if err != nil {
					return jsonStr(map[string]any{"error": err.Error(), "vm_id": vmID})
				}
				if ctype == "" {
					return "", fmt.Errorf("check_type required")
				}
				target := vm.IP
				if target == "" {
					target = vm.Hostname
				}
				if ctype == "dns" && vm.Hostname != "" {
					target = vm.Hostname
				}
				res, err := monitor.RunProbe(ctx, monitor.DefaultRegistry(), ctype, target, argMap(args, "params"))
				if err != nil {
					return jsonStr(map[string]any{"error": err.Error()})
				}
				return jsonStr(map[string]any{
					"status": string(res.Status), "latency_ms": res.LatencyMS,
					"message": res.Message, "detail": res.Detail, "target": target,
				})
			},
		},
		{
			Name: "scan_vm_ports",
			Description: "Wide TCP port scan of a VM (Plane A, no creds): scope=fast (~1k common " +
				"ports, seconds) or full (1-65535, minutes). Finds non-standard open ports the " +
				"common-port scan misses.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id": map[string]any{"type": "integer"},
					"scope": map[string]any{"type": "string", "description": "fast | full"},
				},
				"required": []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				scope := "fast"
				if sc, _ := strArg(args, "scope"); sc == "full" {
					scope = "full"
				}
				_, host, err := vmTarget(ctx, vmID)
				if err != nil {
					return jsonStr(map[string]any{"error": err.Error(), "vm_id": vmID})
				}
				sctx, cancel := context.WithTimeout(ctx, 4*time.Minute)
				defer cancel()
				open := monitor.DeepScan(sctx, host, scope, 1200*time.Millisecond)
				return jsonStr(map[string]any{"host": host, "scope": scope, "open": open, "count": len(open)})
			},
		},
		{
			Name: "scan_vm_exposures",
			Description: "Curated security exposure scan of a VM's public IP (Redis open, Docker " +
				"API, .git/.env leaks, weak TLS...) — credential-free. Result is persisted and " +
				"propagated to all VMs sharing the host, exactly like the UI button.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"vm_id": map[string]any{"type": "integer"}},
				"required":   []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				_, host, err := vmTarget(ctx, vmID)
				if err != nil {
					return jsonStr(map[string]any{"error": err.Error(), "vm_id": vmID})
				}
				if host == "" {
					return jsonStr(map[string]any{"error": "vm has no host/IP to scan"})
				}
				findings := monitor.Exposures(ctx, host, 12*time.Second)
				v := monitor.ExposuresVerdict(findings)
				_, _ = s.PropagateExposuresResult(ctx, 0, host, string(v.Status), v.Message, v.Detail)
				return jsonStr(map[string]any{"host": host, "findings": findings, "verdict": v})
			},
		},
		{
			Name: "get_site_info",
			Description: "Fetch HTTP response headers + security posture + CMS fingerprint for a " +
				"VM's site (or an explicit url http(s)://...). Credential-free.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id": map[string]any{"type": "integer"},
					"url":   map[string]any{"type": "string"},
				},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				url, _ := strArg(args, "url")
				if url == "" {
					vmID, _ := intArg(args, "vm_id")
					_, host, err := vmTarget(ctx, vmID)
					if err != nil {
						return jsonStr(map[string]any{"error": err.Error(), "vm_id": vmID})
					}
					url = "http://" + host
				}
				info, err := monitor.ProbeSite(ctx, url)
				if err != nil {
					return jsonStr(map[string]any{"error": err.Error(), "url": url})
				}
				return jsonStr(info)
			},
		},
		{
			Name: "get_vm_metrics",
			Description: "Stored metric series for a VM (requires metrics collection enabled): " +
				"cpu_pct, mem, swap, disk, load1, tcp_conns, proc_count, net rx/tx. hours = lookback " +
				"window (1-720, default 24). Latest sample included.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id": map[string]any{"type": "integer"},
					"hours": map[string]any{"type": "integer"},
				},
				"required": []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				hours := 24
				if h, ok := intArg(args, "hours"); ok && h > 0 && h <= 720 {
					hours = int(h)
				}
				to := time.Now()
				from := to.Add(-time.Duration(hours) * time.Hour)
				out := map[string]any{"hours": hours, "series": map[string]any{}}
				for _, name := range []string{"mem_used_mb", "mem_total_mb", "disk_used_gb", "disk_total_gb", "load1", "cpu_pct", "tcp_conns", "proc_count", "net_rx_kbps", "net_tx_kbps"} {
					pts, err := s.MetricSeries(ctx, vmID, name, from, to)
					if err != nil {
						continue
					}
					arr := make([][2]any, 0, len(pts))
					for _, p := range pts {
						arr = append(arr, [2]any{p.TS.Unix(), p.Value})
					}
					out["series"].(map[string]any)[name] = arr
				}
				return jsonStr(out)
			},
		},
		{
			Name: "get_vm_snapshot",
			Description: "LIVE resource snapshot of a VM over SSH (CPU/RAM/disk/load/uptime/top " +
				"processes). Requires ai access + stored credentials for that VM.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"vm_id": map[string]any{"type": "integer"}},
				"required":   []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				return sshRead(ctx, vmID, func() (any, error) { return reader.Snapshot(ctx, vmID) })
			},
		},
		{
			Name: "get_vm_errors",
			Description: "Recent system errors of a VM over SSH (journalctl/syslog priority err). " +
				"window: '24h' (default) or e.g. '3h', '7d'. Requires ai access + credentials.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id": map[string]any{"type": "integer"},
					"range": map[string]any{"type": "string"},
				},
				"required": []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				window, _ := strArg(args, "range")
				if window == "" {
					window = "24h"
				}
				return sshRead(ctx, vmID, func() (any, error) { return reader.Errors(ctx, vmID, window) })
			},
		},
		{
			Name: "get_vm_updates",
			Description: "Pending package updates of a VM over SSH: upgradable count, security " +
				"subset, reboot-required flag. Requires ai access + credentials.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"vm_id": map[string]any{"type": "integer"}},
				"required":   []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				return sshRead(ctx, vmID, func() (any, error) { return reader.Updates(ctx, vmID) })
			},
		},
		{
			Name: "refresh_vm_inventory",
			Description: "Re-scan a VM's system profile over SSH (OS, ports, docker, services) and " +
				"store it — the inventory refresh button of the UI. Requires ai access + credentials.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"vm_id": map[string]any{"type": "integer"}},
				"required":   []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				return sshRead(ctx, vmID, func() (any, error) { return reader.InventoryRefresh(ctx, vmID) })
			},
		},
		{
			Name: "get_vm_vhosts",
			Description: "Web-server virtual hosts of a VM over SSH (nginx/apache server_name list). " +
				"Requires ai access + credentials.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"vm_id": map[string]any{"type": "integer"}},
				"required":   []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				return sshRead(ctx, vmID, func() (any, error) { return reader.VHosts(ctx, vmID) })
			},
		},
		{
			Name: "update_vm",
			Description: "Edit a VM's metadata: name, tags (array of strings), notes, provider, " +
				"location_country, location_city, cost_monthly, currency; folds: alert_muted " +
				"(exclude from fleet-wide alert rules), metrics_enabled (collect CPU/RAM/disk). " +
				"Only provided fields change. Credentials/ai-access stay web-only.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id":            map[string]any{"type": "integer"},
					"name":             map[string]any{"type": "string"},
					"tags":             map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
					"notes":            map[string]any{"type": "string"},
					"provider":         map[string]any{"type": "string"},
					"location_country": map[string]any{"type": "string"},
					"location_city":    map[string]any{"type": "string"},
					"cost_monthly":     map[string]any{"type": "number"},
					"currency":         map[string]any{"type": "string"},
					"alert_muted":      map[string]any{"type": "boolean"},
					"metrics_enabled":  map[string]any{"type": "boolean"},
					"kind":             map[string]any{"type": "string", "description": "server | equipment"},
				},
				"required": []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				vm, err := s.GetVM(ctx, vmID)
				if err != nil {
					return jsonStr(map[string]any{"error": "vm not found", "vm_id": vmID})
				}
				changed := []string{}
				if v, ok := strArg(args, "name"); ok && v != "" {
					vm.Name, _ = strings.CutSuffix(v, "")
					vm.Name = v
					changed = append(changed, "name")
				}
				if v, ok := strArg(args, "notes"); ok {
					vm.Notes = v
					changed = append(changed, "notes")
				}
				if v, ok := strArg(args, "provider"); ok {
					vm.Provider = v
					changed = append(changed, "provider")
				}
				if v, ok := strArg(args, "location_country"); ok {
					vm.LocationCountry = v
					changed = append(changed, "location_country")
				}
				if v, ok := strArg(args, "location_city"); ok {
					vm.LocationCity = v
					changed = append(changed, "location_city")
				}
				if v, ok := strArg(args, "currency"); ok {
					vm.Currency = v
					changed = append(changed, "currency")
				}
				if raw, ok := args["tags"].([]any); ok {
					tags := make([]string, 0, len(raw))
					for _, t := range raw {
						if sv, ok := t.(string); ok {
							tags = append(tags, sv)
						}
					}
					vm.Tags = tags
					changed = append(changed, "tags")
				}
				if raw, ok := args["cost_monthly"].(float64); ok {
					vm.CostMonthly = &raw
					changed = append(changed, "cost_monthly")
				}
				if k, ok := strArg(args, "kind"); ok && k != "" {
					if !store.ValidVMKind(k) {
						return jsonStr(map[string]any{"error": "invalid kind: must be server or equipment"})
					}
					vm.Kind = k
					changed = append(changed, "kind")
				}
				if len(changed) > 0 {
					if err := s.UpdateVM(ctx, vm); err != nil {
						var ve store.ValidationError
						if asValidation(err, &ve) {
							return jsonStr(map[string]any{"error": "invalid vm: " + ve.Error(), "field": ve.Field})
						}
						return "", err
					}
				}
				// Folds handled by their own store paths.
				if raw, ok := args["alert_muted"].(bool); ok {
					if err := s.SetAlertMute(ctx, vmID, raw); err != nil {
						return jsonStr(map[string]any{"error": "alert_mute: " + err.Error()})
					}
					changed = append(changed, "alert_muted="+strconv.FormatBool(raw))
				}
				if raw, ok := args["metrics_enabled"].(bool); ok {
					if err := s.SetMetricsEnabled(ctx, vmID, raw); err != nil {
						return jsonStr(map[string]any{"error": "metrics_enabled: " + err.Error()})
					}
					changed = append(changed, "metrics_enabled="+strconv.FormatBool(raw))
				}
				if len(changed) == 0 {
					return jsonStr(map[string]any{"ok": true, "changed": []string{}, "note": "nothing to change"})
				}
				auditAppendAI(s, "ai_update_vm", "vm", strconv.FormatInt(vmID, 10), true)
				return jsonStr(map[string]any{"ok": true, "changed": changed})
			},
		},
	}
	return tools
}

// argMap reads a nested object arg (JSON-decoded map).
func argMap(args map[string]any, key string) map[string]any {
	if m, ok := args[key].(map[string]any); ok {
		return m
	}
	return nil
}
