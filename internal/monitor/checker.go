// Package monitor implements the Plane A check-execution engine.
//
// region MODULE_CONTRACT [DOMAIN(8): Monitoring; CONCEPT(8): PlaneA; TECH(8): net,goroutines]
// @purpose Define the Checker abstraction and registry so new check types plug in without
//
//	touching the engine. Plane A: always-on, no master passphrase, no SSH credentials.
//
// @invariants
//   - A Checker NEVER panics; failures are returned as Result{Status: critical|unknown}.
//   - Status domain is closed: ok | warn | critical | unknown.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: monitor, Checker, Result, Status, Registry, Plane A, thresholds
// STRUCTURE: ▶ ┌Checker┐ → ○ Run(ctx,target,params) → ⊕ Result → 〈applyThresholds〉 → ⎷
package monitor

import (
	"context"
	"sync"
)

// region STRUCT_Status [DOMAIN(7): Monitoring; CONCEPT(6): Enum; TECH(4): type]
// @purpose Closed status domain for check results.
// endregion STRUCT_Status
type Status string

const (
	StatusOK       Status = "ok"
	StatusWarn     Status = "warn"
	StatusCritical Status = "critical"
	StatusUnknown  Status = "unknown"
)

// region STRUCT_Result [DOMAIN(8): Monitoring; CONCEPT(7): Outcome; TECH(6): struct]
// @purpose The normalized outcome of one check execution.
// endregion STRUCT_Result
type Result struct {
	Status    Status         `json:"status"`
	LatencyMS float64        `json:"latency_ms"`
	Message   string         `json:"message"`
	Detail    map[string]any `json:"detail"`
}

// region STRUCT_Checker [DOMAIN(8): Monitoring; CONCEPT(8): Plugin; TECH(7): interface]
// @purpose A single check type. Implementations are registered in a Registry.
// endregion STRUCT_Checker
type Checker interface {
	// Type returns the check_type key this implementation handles (e.g. "tcp", "http").
	Type() string
	// Run executes the check. Implementations MUST NOT panic; return a Result always.
	Run(ctx context.Context, target string, params map[string]any) Result
}

// region STRUCT_Registry [DOMAIN(7): Monitoring; CONCEPT(7): PluginRegistry; TECH(6): map]
// @purpose Map check_type -> Checker. Thread-safe; the engine reads via Get.
// endregion STRUCT_Registry
type Registry struct {
	mu sync.RWMutex
	m  map[string]Checker
}

// region FUNC_NewRegistry [DOMAIN(7): Monitoring; CONCEPT(6): Build; TECH(5): map]
// @purpose Build a registry pre-populated with the given checkers.
// @complexity 2
// endregion FUNC_NewRegistry
func NewRegistry(checkers ...Checker) *Registry {
	r := &Registry{m: make(map[string]Checker, len(checkers))}
	for _, c := range checkers {
		r.Register(c)
	}
	return r
}

// region FUNC_Registry_Register [DOMAIN(7): Monitoring; CONCEPT(6): Mutate; TECH(5): map]
// @purpose Add or replace a checker by its Type().
// @complexity 2
// endregion FUNC_Registry_Register
func (r *Registry) Register(c Checker) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[c.Type()] = c
}

// region FUNC_Registry_Get [DOMAIN(7): Monitoring; CONCEPT(6): Lookup; TECH(5): map]
// @purpose Fetch a checker by type.
// @complexity 2
// endregion FUNC_Registry_Get
func (r *Registry) Get(t string) (Checker, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.m[t]
	return c, ok
}

// region FUNC_applyThresholds [DOMAIN(7): Monitoring; CONCEPT(7): Rules; TECH(5): pure]
// @purpose Promote an ok result to warn/critical when latency exceeds configured thresholds.
//
//	Reads params "latency_ms" (warn) and "critical_latency_ms" (critical) from thresholds.
//	Non-ok results pass through unchanged.
//
// @complexity 3
// endregion FUNC_applyThresholds
func applyThresholds(res Result, thresholds map[string]any) Result {
	if res.Status != StatusOK || thresholds == nil {
		return res
	}
	if crit, ok := num(thresholds["critical_latency_ms"]); ok && res.LatencyMS > crit {
		res.Status = StatusCritical
		res.Message = res.Message + " (critical latency)"
		return res
	}
	if warn, ok := num(thresholds["latency_ms"]); ok && res.LatencyMS > warn {
		res.Status = StatusWarn
		res.Message = res.Message + " (high latency)"
		return res
	}
	return res
}

// num coerces a JSON-decoded numeric (float64) or int to float64.
func num(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	}
	return 0, false
}

// DefaultRegistry returns a registry with all built-in checkers registered.
func DefaultRegistry() *Registry {
	return NewRegistry(
		&TCPChecker{},
		&HTTPChecker{},
		&TLSChecker{},
		&DNSChecker{},
		&DNSBLChecker{},
		&WhoisChecker{},
		&PingChecker{},
	)
}
