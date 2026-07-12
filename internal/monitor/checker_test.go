// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): Registry; TECH(8): go test]
// @purpose Verify Registry Get/Register and applyThresholds promotion rules.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, registry, thresholds, applyThresholds, warn, critical
// STRUCTURE: ▶ ┌Result┐ → ○ applyThresholds → 〈latency? warn/crit〉 → ⎋ assert
package monitor

import (
	"context"
	"testing"
)

type fakeChecker struct{ typ string }

func (f fakeChecker) Type() string { return f.typ }
func (f fakeChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	return Result{Status: StatusOK}
}

func TestRegistry_RegisterGet(t *testing.T) {
	r := NewRegistry(fakeChecker{"tcp"}, fakeChecker{"http"})
	if _, ok := r.Get("tcp"); !ok {
		t.Fatal("expected tcp registered")
	}
	if _, ok := r.Get("nope"); ok {
		t.Fatal("unexpected checker for 'nope'")
	}
	r.Register(fakeChecker{"tls"})
	if _, ok := r.Get("tls"); !ok {
		t.Fatal("tls not registered after Register")
	}
}

func TestDefaultRegistry_HasAllTypes(t *testing.T) {
	r := DefaultRegistry()
	for _, typ := range []string{"tcp", "http", "tls", "whois", "ping"} {
		if _, ok := r.Get(typ); !ok {
			t.Errorf("default registry missing %q", typ)
		}
	}
}

func TestApplyThresholds(t *testing.T) {
	cases := []struct {
		name string
		res  Result
		th   map[string]any
		want Status
	}{
		{"ok under warn", Result{Status: StatusOK, LatencyMS: 50}, map[string]any{"latency_ms": 100.0}, StatusOK},
		{"over warn", Result{Status: StatusOK, LatencyMS: 150}, map[string]any{"latency_ms": 100.0}, StatusWarn},
		{"over critical", Result{Status: StatusOK, LatencyMS: 500}, map[string]any{"latency_ms": 100.0, "critical_latency_ms": 400.0}, StatusCritical},
		{"non-ok passthrough", Result{Status: StatusCritical, LatencyMS: 999}, map[string]any{"latency_ms": 1.0}, StatusCritical},
	}
	for _, c := range cases {
		got := applyThresholds(c.res, c.th)
		if got.Status != c.want {
			t.Errorf("%s: want %s got %s", c.name, c.want, got.Status)
		}
	}
}
