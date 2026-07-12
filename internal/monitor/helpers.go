// Package monitor — param helpers shared by checkers.
//
// region MODULE_CONTRACT [DOMAIN(6): Monitoring; CONCEPT(6): Params; TECH(5): map]
// @purpose Coerce JSON-decoded checker params (float64/int/string) into typed values with
//
//	safe defaults, so checkers never panic on missing/odd params.
//
// @invariants
//   - Every helper returns a usable default when the key is absent or mistyped.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: params, helper, port, timeout, coerce, defaults
// STRUCTURE: ▶ ┌params[key]┐ → 〈type-switch〉 → ⊕ default|value → ⎷ typed
package monitor

import (
	"fmt"
	"strconv"
	"time"
)

func strOf(params map[string]any, key, def string) string {
	if params == nil {
		return def
	}
	if v, ok := params[key]; ok {
		switch x := v.(type) {
		case string:
			if x != "" {
				return x
			}
		case float64:
			return fmt.Sprintf("%v", x)
		case int:
			return fmt.Sprintf("%d", x)
		}
	}
	return def
}

func intOf(params map[string]any, key string, def int) int {
	if v, ok := num(get(params, key)); ok {
		return int(v)
	}
	return def
}

// portOf returns a port string; accepts int/float/string; defaults to def when absent/invalid.
func portOf(params map[string]any, def int) string {
	if params != nil {
		switch x := params["port"].(type) {
		case string:
			if p, err := strconv.Atoi(x); err == nil && p >= 1 && p <= 65535 {
				return x
			}
		case float64:
			p := int(x)
			if p >= 1 && p <= 65535 {
				return fmt.Sprintf("%d", p)
			}
		case int:
			if x >= 1 && x <= 65535 {
				return fmt.Sprintf("%d", x)
			}
		}
	}
	return fmt.Sprintf("%d", def)
}

// timeoutOf returns a timeout; reads "timeout_sec" (float ok) and clamps to [1s, 30s].
func timeoutOf(params map[string]any, def time.Duration) time.Duration {
	if v, ok := num(get(params, "timeout_sec")); ok {
		d := time.Duration(v*1000) * time.Millisecond
		if d >= time.Second && d <= 30*time.Second {
			return d
		}
	}
	return def
}

// boolOf reads a boolean param; accepts bool or numeric truthiness.
func boolOf(params map[string]any, key string, def bool) bool {
	if params == nil {
		return def
	}
	switch x := params[key].(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case int:
		return x != 0
	}
	return def
}

func get(params map[string]any, key string) any {
	if params == nil {
		return nil
	}
	return params[key]
}
