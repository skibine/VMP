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
	"sync"

	"github.com/skibine/vm-pulse/internal/health"
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
			Description: "List the virtual machines the operator has granted the assistant access to (ai_enabled), with their ids, names, hostnames and tags.",
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
				}
				out := make([]vmSum, 0, len(vms))
				for _, v := range vms {
					if !v.AIEnabled { // per-VM opt-in: only granted VMs are visible to the model
						continue
					}
					out = append(out, vmSum{v.ID, v.Name, v.Hostname, v.IP, v.Tags})
				}
				return jsonStr(out)
			},
		},
		{
			Name:        "get_vm_health",
			Description: "Get the K2 health-score (0-100) and status for a VM by its id (only if ai access is granted).",
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
			Description: "List the latest result of each check for a VM by its id (only if ai access is granted).",
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
			Name:        "list_alerts",
			Description: "List the most recently fired alerts (newest first).",
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
				return jsonStr(alerts)
			},
		},
	}
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
