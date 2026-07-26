// Package health computes the K2 health-score: a single 0-100 number + status derived from a
// set of check statuses.
//
// region MODULE_CONTRACT [DOMAIN(8): Health; CONCEPT(8): Scoring; TECH(6): pure]
// @purpose Turn many per-check statuses into one glanceable indicator (score + color) for the
//
//	dashboard. Decoupled from storage: callers map their rows into []CheckStatus.
//
// @io Compute([]CheckStatus, Weights) -> Score
// @invariants
//   - Compute is pure: same input -> same output, no I/O.
//   - Score 0-100 (average of per-check points); status is the WORST real check status
//     (critical> warn> ok), so one failing check colors the VM red even if the average is high.
//   - Pending/unknown checks do not change status unless ALL checks are pending -> unknown.
//   - No checks -> status unknown, score 0.
//
// @rationale
//
//	Q: Why worst-status for the color but average for the number?
//	A: Operators expect "red means something is red"; the average still communicates overall
//	   wear. Weights stay tunable for Phase-0 re-tuning (foundation-v2 §12.4).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: health, score, K2, Compute, weights, worst status, ok, warn, critical, unknown
// STRUCTURE: ▶ ┌checks┐ → ○ points(status) ∑ avg → ⊕ worstRank → 〈status〉 → ⎷ Score
package health

// Status constants (mirror monitor statuses; kept here to avoid importing monitor).
const (
	StatusOK       = "ok"
	StatusWarn     = "warn"
	StatusCritical = "critical"
	StatusUnknown  = "unknown"
)

// region STRUCT_Weights [DOMAIN(7): Health; CONCEPT(6): Tuning; TECH(4): struct]
// @purpose Points awarded per check status. Tunable; defaults are the Phase-0 choice.
// endregion STRUCT_Weights
type Weights struct {
	OK       int
	Unknown  int // includes "pending" (check exists, never ran)
	Warn     int
	Critical int
}

// DefaultWeights returns the Phase-0 default point mapping.
func DefaultWeights() Weights {
	return Weights{OK: 100, Unknown: 70, Warn: 40, Critical: 0}
}

// region STRUCT_CheckStatus [DOMAIN(7): Health; CONCEPT(6): Input; TECH(5): struct]
// @purpose Input row: one check's latest status (Status empty == never ran).
// endregion STRUCT_CheckStatus
type CheckStatus struct {
	CheckID   int64   `json:"check_id"`
	CheckType string  `json:"check_type"`
	Status    string  `json:"status"`
	LatencyMS float64 `json:"latency_ms"`
	Message   string  `json:"message"`
}

// region STRUCT_Score [DOMAIN(7): Health; CONCEPT(7): Output; TECH(5): struct]
// @purpose The glanceable health indicator for one VM.
// endregion STRUCT_Score
type Score struct {
	Score     int           `json:"score"`
	Status    string        `json:"status"`
	Breakdown []CheckStatus `json:"breakdown"`
}

// region FUNC_Compute [DOMAIN(8): Health; CONCEPT(8): Score; TECH(5): pure]
// @purpose Compute score (avg points) and status (worst real check) from check statuses.
// @complexity 4
// endregion FUNC_Compute
func Compute(checks []CheckStatus, w Weights) Score {
	if w == (Weights{}) {
		w = DefaultWeights()
	}
	if len(checks) == 0 {
		return Score{Score: 0, Status: StatusUnknown, Breakdown: checks}
	}
	sum := 0
	worstRank := -1 // -1 = no real (ok/warn/critical) status seen
	for _, c := range checks {
		sum += points(c.Status, w)
		if r := rank(c.Status); r > worstRank {
			worstRank = r
		}
	}
	score := sum / len(checks)
	var status string
	switch {
	case worstRank < 0:
		status = StatusUnknown // all pending/unknown
	case worstRank == 2:
		status = StatusCritical
	case worstRank == 1:
		status = StatusWarn
	default:
		status = StatusOK
	}
	return Score{Score: score, Status: status, Breakdown: checks}
}

// points maps a status string to its score contribution; empty/unknown -> Unknown points.
func points(status string, w Weights) int {
	switch status {
	case StatusOK:
		return w.OK
	case StatusWarn:
		return w.Warn
	case StatusCritical:
		return w.Critical
	}
	return w.Unknown // unknown or "" (pending)
}

// rank returns severity for real statuses; -1 for unknown/pending (excluded from worst).
func rank(status string) int {
	switch status {
	case StatusCritical:
		return 2
	case StatusWarn:
		return 1
	case StatusOK:
		return 0
	}
	return -1
}
