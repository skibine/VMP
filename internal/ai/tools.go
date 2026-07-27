// Package ai — tool registry and the v0 read-only tool set over Plane A state.
//
// region MODULE_CONTRACT [DOMAIN(9): AI; CONCEPT(8): Tools; TECH(7): store,health,json]
// @purpose Expose VM Pulse data to the model as callable tools. v0 is strictly READ-ONLY:
//
//	no tool mutates state (mutating actions arrive in a later Plane-B slice).
//
// @invariants
//   - Every tool returns a JSON string (the model consumes tool results as text).
//   - A tool error is returned to the caller (agent), not panicked.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: tools, registry, list_vms, get_vm_health, list_vm_results, list_alerts, read-only
// STRUCTURE: ▶ ┌store┐ → ⊕ StoreTools → ○ Registry.Run(name,args) → 〈json〉 → ⎷ string
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/skibine/vm-pulse/internal/health"
	"github.com/skibine/vm-pulse/internal/monitor"
	"github.com/skibine/vm-pulse/internal/store"
)

// region STRUCT_Registry [DOMAIN(8): AI; CONCEPT(7): ToolRegistry; TECH(6): map]
// @purpose Map tool name -> Tool; thread-safe.
// endregion STRUCT_Registry
type Registry struct {
	mu sync.RWMutex
	m  map[string]Tool
}

func NewRegistry(tools ...Tool) *Registry {
	r := &Registry{m: make(map[string]Tool, len(tools))}
	for _, t := range tools {
		r.Register(t)
	}
	return r
}

func (r *Registry) Register(t Tool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[t.Name] = t
}

func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.m[name]
	return t, ok
}

// Tools returns all registered tools (for passing schemas to the model).
func (r *Registry) Tools() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Tool, 0, len(r.m))
	for _, t := range r.m {
		out = append(out, t)
	}
	return out
}

// Run executes a tool by name with parsed args.
func (r *Registry) Run(ctx context.Context, name string, args map[string]any) (string, error) {
	t, ok := r.Get(name)
	if !ok {
		return "", fmt.Errorf("unknown tool: %s", name)
	}
	if t.Run == nil {
		return "", fmt.Errorf("tool %s has no handler", name)
	}
	return t.Run(ctx, args)
}

// region FUNC_StoreTools [DOMAIN(8): AI; CONCEPT(7): Factory; TECH(6): closure]
// @purpose Build the v0 read-only tool set bound to a store.
// @complexity 4
// endregion FUNC_StoreTools
func StoreTools(s *store.Store) []Tool {
	return []Tool{
		{
			Name:        "list_vms",
			Description: "List ALL virtual machines in the fleet with id, name, hostname, ip, tags, liveness status (ok|warn|critical|unknown), and ai_access (true = you may run commands on that VM). The whole fleet is visible so you can target any VM's IP; ai_access only gates command execution and deep data.",
			Parameters:  map[string]any{"type": "object", "properties": map[string]any{}},
			Run: func(ctx context.Context, _ map[string]any) (string, error) {
				vms, err := s.ListVMs(ctx, false)
				if err != nil {
					return "", err
				}
				type vmSum struct {
					ID       int64    `json:"id"`
					Name     string   `json:"name"`
					Hostname string   `json:"hostname"`
					IP       string   `json:"ip"`
					Tags     []string `json:"tags"`
					AIAccess bool     `json:"ai_access"` // true = command execution + deep data allowed
					Status   string   `json:"status"`    // ok|warn|critical|unknown
				}
				out := make([]vmSum, 0, len(vms))
				for _, v := range vms {
					// Fleet metadata (name/IP/liveness) is visible for EVERY VM; ai_access only
					// gates mutation/deep-data. This lets the model target any IP (e.g. traceroute
					// from a granted VM to a non-granted one) without blind spots.
					status := "unknown"
					if rows, err := s.LatestResultsForVM(ctx, v.ID); err == nil {
						checks := make([]health.CheckStatus, 0, len(rows))
						for _, row := range rows {
							if row.Enabled {
								checks = append(checks, health.CheckStatus{
									CheckID: row.CheckID, CheckType: row.CheckType,
									Status: row.LatestStatus, LatencyMS: row.LatestLatency,
								})
							}
						}
						status = health.Compute(checks, health.DefaultWeights()).Status
					}
					out = append(out, vmSum{v.ID, v.Name, v.Hostname, v.IP, v.Tags, v.AIEnabled, status})
				}
				return jsonStr(out)
			},
		},
		{
			Name:        "get_vm_health",
			Description: "Get the liveness health-score (0-100) and status (ok|warn|critical|unknown) for any VM by id. Liveness is fleet-wide overview; available for every VM.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"vm_id": map[string]any{"type": "integer"}},
				"required":   []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				id, ok := intArg(args, "vm_id")
				if !ok {
					return "", fmt.Errorf("vm_id required")
				}
				if _, err := s.GetVM(ctx, id); err != nil {
					return jsonStr(map[string]any{"error": "vm not found", "vm_id": id})
				}
				rows, err := s.LatestResultsForVM(ctx, id)
				if err != nil {
					return "", err
				}
				checks := make([]health.CheckStatus, 0, len(rows))
				for _, row := range rows {
					if !row.Enabled {
						continue
					}
					checks = append(checks, health.CheckStatus{
						CheckID: row.CheckID, CheckType: row.CheckType,
						Status: row.LatestStatus, LatencyMS: row.LatestLatency,
					})
				}
				score := health.Compute(checks, health.DefaultWeights())
				return jsonStr(score)
			},
		},
		{
			Name:        "list_vm_results",
			Description: "List the latest result of each check for a VM by id. Requires ai_access for that VM (detailed per-VM operational data).",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"vm_id": map[string]any{"type": "integer"}},
				"required":   []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				id, ok := intArg(args, "vm_id")
				if !ok {
					return "", fmt.Errorf("vm_id required")
				}
				vm, err := s.GetVM(ctx, id)
				if err != nil {
					return jsonStr(map[string]any{"error": "vm not found", "vm_id": id})
				}
				if !vm.AIEnabled {
					return jsonStr(map[string]any{"error": "ai access disabled for this vm", "vm_id": id})
				}
				rows, err := s.LatestResultsForVM(ctx, id)
				if err != nil {
					return "", err
				}
				return jsonStr(rows)
			},
		},
		{
			Name:        "get_vm_inventory",
			Description: "Get the scanned system profile for a VM (OS, listening ports, docker containers, package/services counts, running services) — the inventory gathered from SSH. Only if ai access is granted.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"vm_id": map[string]any{"type": "integer"}},
				"required":   []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				id, ok := intArg(args, "vm_id")
				if !ok {
					return "", fmt.Errorf("vm_id required")
				}
				vm, err := s.GetVM(ctx, id)
				if err != nil {
					return jsonStr(map[string]any{"error": "vm not found", "vm_id": id})
				}
				if !vm.AIEnabled {
					return jsonStr(map[string]any{"error": "ai access disabled for this vm", "vm_id": id})
				}
				creds, has, err := s.GetVMCredentials(ctx, id)
				if err != nil || !has || creds.Inventory == "" {
					return jsonStr(map[string]any{"vm_id": id, "inventory": nil, "note": "no SSH inventory scanned yet"})
				}
				var inv any
				if err := json.Unmarshal([]byte(creds.Inventory), &inv); err != nil {
					return jsonStr(map[string]any{"vm_id": id, "inventory": nil, "note": "inventory parse error"})
				}
				return jsonStr(map[string]any{"vm_id": id, "inventory": inv})
			},
		},
		{
			Name:        "list_alerts",
			Description: "List recently fired alerts (newest first), only for VMs the operator granted the assistant access to (ai_enabled).",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"limit": map[string]any{"type": "integer"}},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				limit := 20
				if n, ok := intArg(args, "limit"); ok && n > 0 {
					limit = int(n)
				}
				alerts, err := s.ListAlerts(ctx, limit)
				if err != nil {
					return "", err
				}
				// Per-VM opt-in: drop alerts tied to a non-granted VM. Domain alerts (vm_id nil) pass.
				granted, err := aiGrantedVMIDs(ctx, s)
				if err != nil {
					return "", err
				}
				out := make([]store.Alert, 0, len(alerts))
				for _, a := range alerts {
					if a.VMID != nil && !granted[*a.VMID] {
						continue
					}
					out = append(out, a)
				}
				return jsonStr(out)
			},
		},
	}
}

// HostProbeTools returns Plane A tools that probe a target FROM the VM Pulse host itself — no VM
// credentials needed and no ai_access required. These are what let the assistant "ping"/check ANY
// target (a VM IP, a domain, an external host) even when no VM has SSH access granted: the host can
// always reach the network. TCP-based, so they work on Windows without elevation (unlike ICMP).
func HostProbeTools() []Tool {
	return []Tool{
		{
			Name: "probe_host",
			Description: "Probe any host (IP or hostname) directly from the VM Pulse host — NO VM credentials and NO ai_access needed. " +
				"Runs a TCP port scan of common ports (22/80/443/3306/...) plus a curated security exposure scan. " +
				"This is how you check reachability (the 'ping' question) and exposures of ANY target: a VM IP you have no SSH access to, a domain, or an external host. " +
				"If at least one common port answers, the host is UP. Use this instead of trying to run ping over SSH.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"target": map[string]any{"type": "string", "description": "IP address or hostname to probe"},
				},
				"required": []string{"target"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				target, _ := args["target"].(string)
				target = strings.TrimSpace(target)
				if target == "" {
					return "", fmt.Errorf("target is required")
				}
				ports := monitor.PortScan(ctx, target, 8*time.Second)
				findings := monitor.Exposures(ctx, target, 8*time.Second)
				open := 0
				for _, p := range ports {
					if p.Open {
						open++
					}
				}
				return jsonStr(map[string]any{
					"target": target, "up": open > 0, "open_ports": open,
					"ports": ports, "exposures": findings,
				})
			},
		},
	}
}

// aiGrantedVMIDs returns the set of VM ids the operator has granted the assistant access to.
func aiGrantedVMIDs(ctx context.Context, s *store.Store) (map[int64]bool, error) {
	vms, err := s.ListVMs(ctx, false)
	if err != nil {
		return nil, err
	}
	set := make(map[int64]bool, len(vms))
	for _, v := range vms {
		if v.AIEnabled {
			set[v.ID] = true
		}
	}
	return set, nil
}

// jsonStr marshals v to a JSON string (never returns an error for these simple types).
func jsonStr(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// intArg reads an integer arg from JSON-decoded map (float64/int).
func intArg(args map[string]any, key string) (int64, bool) {
	if args == nil {
		return 0, false
	}
	switch x := args[key].(type) {
	case float64:
		return int64(x), true
	case int:
		return int64(x), true
	case int64:
		return x, true
	}
	return 0, false
}
