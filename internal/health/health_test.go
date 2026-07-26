// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): Scoring; TECH(8): go test]
// @purpose Verify health.Compute matrix with worst-status bias: all-ok, critical-drag,
//
//	warn-mix, all-pending, no-checks.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, health, Compute, score, worst status, matrix
// STRUCTURE: ▶ ┌cases┐ → ○ Compute → 〈score/status?〉 → ⎋ assert
package health

import "testing"

func TestCompute_Matrix(t *testing.T) {
	w := DefaultWeights()
	cases := []struct {
		name       string
		checks     []CheckStatus
		wantScore  int
		wantStatus string
	}{
		{"all ok", []CheckStatus{{CheckID: 1, CheckType: "tcp", Status: StatusOK, LatencyMS: 1}, {CheckID: 2, CheckType: "http", Status: StatusOK, LatencyMS: 2}}, 100, StatusOK},
		{"one critical of four -> red", []CheckStatus{
			{CheckID: 1, CheckType: "tcp", Status: StatusOK, LatencyMS: 1}, {CheckID: 2, CheckType: "http", Status: StatusOK, LatencyMS: 1}, {CheckID: 3, CheckType: "tls", Status: StatusOK, LatencyMS: 1}, {CheckID: 4, CheckType: "ping", Status: StatusCritical, LatencyMS: 0},
		}, 75, StatusCritical},
		{"warn mix", []CheckStatus{{CheckID: 1, CheckType: "tcp", Status: StatusOK, LatencyMS: 1}, {CheckID: 2, CheckType: "http", Status: StatusWarn, LatencyMS: 1}}, 70, StatusWarn},
		{"all pending -> unknown", []CheckStatus{{CheckID: 1, CheckType: "tcp", Status: "", LatencyMS: 0}, {CheckID: 2, CheckType: "http", Status: "", LatencyMS: 0}}, w.Unknown, StatusUnknown},
		{"ok + pending -> ok", []CheckStatus{{CheckID: 1, CheckType: "tcp", Status: StatusOK, LatencyMS: 1}, {CheckID: 2, CheckType: "http", Status: "", LatencyMS: 0}}, (w.OK + w.Unknown) / 2, StatusOK},
		{"no checks", []CheckStatus{}, 0, StatusUnknown},
	}
	for _, c := range cases {
		got := Compute(c.checks, w)
		if got.Score != c.wantScore || got.Status != c.wantStatus {
			t.Errorf("%s: want (%d,%s) got (%d,%s)", c.name, c.wantScore, c.wantStatus, got.Score, got.Status)
		}
		if len(got.Breakdown) != len(c.checks) {
			t.Errorf("%s: breakdown length mismatch", c.name)
		}
	}
}

func TestCompute_DefaultsWhenZero(t *testing.T) {
	// Zero Weights -> defaults applied (not all-critical).
	got := Compute([]CheckStatus{{CheckID: 1, CheckType: "tcp", Status: StatusOK, LatencyMS: 1}}, Weights{})
	if got.Score != 100 || got.Status != StatusOK {
		t.Fatalf("zero-value opts should fall back to defaults, got %+v", got)
	}
}
