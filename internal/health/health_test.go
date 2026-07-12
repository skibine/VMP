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
		{"all ok", []CheckStatus{{1, "tcp", StatusOK, 1}, {2, "http", StatusOK, 2}}, 100, StatusOK},
		{"one critical of four -> red", []CheckStatus{
			{1, "tcp", StatusOK, 1}, {2, "http", StatusOK, 1}, {3, "tls", StatusOK, 1}, {4, "ping", StatusCritical, 0},
		}, 75, StatusCritical},
		{"warn mix", []CheckStatus{{1, "tcp", StatusOK, 1}, {2, "http", StatusWarn, 1}}, 70, StatusWarn},
		{"all pending -> unknown", []CheckStatus{{1, "tcp", "", 0}, {2, "http", "", 0}}, w.Unknown, StatusUnknown},
		{"ok + pending -> ok", []CheckStatus{{1, "tcp", StatusOK, 1}, {2, "http", "", 0}}, (w.OK + w.Unknown) / 2, StatusOK},
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
	got := Compute([]CheckStatus{{1, "tcp", StatusOK, 1}}, Weights{})
	if got.Score != 100 || got.Status != StatusOK {
		t.Fatalf("zero-value opts should fall back to defaults, got %+v", got)
	}
}
