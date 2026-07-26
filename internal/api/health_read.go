// Package api — read endpoints for check results and K2 health-score.
//
// region MODULE_CONTRACT [DOMAIN(7): API; CONCEPT(7): Read; TECH(8): net/http,go1.22routing]
// @purpose Expose per-VM latest results and the computed health-score for the dashboard.
// @invariants
//   - Lists are never null in JSON (empty array when no data).
//   - Unknown VM id -> 404.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: results, health, score, K2, vmResults, vmHealth, read, endpoint
// STRUCTURE: ▶ ┌vmID┐ → ○ LatestResultsForVM → 〈/health? Compute〉 → ⊕ JSON → ⎷
package api

import (
	"net/http"
	"strconv"

	"github.com/skibine/vm-pulse/internal/health"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// region FUNC_vmResults [DOMAIN(7): API; CONCEPT(6): Read; TECH(6): net/http]
// @purpose Return the latest result of each check for a VM (breakdown for the dashboard).
// @complexity 3
// endregion FUNC_vmResults
func (a *crudAPI) vmResults(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	rows, err := a.st.LatestResultsForVM(r.Context(), id)
	if err != nil {
		a.writeErr(w, "vmResults", err)
		return
	}
	if rows == nil {
		rows = []store.VMCheckStatus{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// region FUNC_vmHealth [DOMAIN(7): API; CONCEPT(7): Health; TECH(7): net/http]
// @purpose Compute and return the K2 health-score for a VM.
// @complexity 4
// endregion FUNC_vmHealth
func (a *crudAPI) vmHealth(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	exists, err := a.st.VMExists(r.Context(), id)
	if err != nil {
		a.writeErr(w, "vmHealth", err)
		return
	}
	if !exists {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
		return
	}
	rows, err := a.st.LatestResultsForVM(r.Context(), id)
	if err != nil {
		a.writeErr(w, "vmHealth", err)
		return
	}
	checks := make([]health.CheckStatus, 0, len(rows))
	for _, row := range rows {
		if !row.Enabled {
			continue
		}
		checks = append(checks, health.CheckStatus{
			CheckID: row.CheckID, CheckType: row.CheckType,
			Status: row.LatestStatus, LatencyMS: row.LatestLatency, Message: row.LatestMessage,
		})
	}
	score := health.Compute(checks, health.DefaultWeights())
	logging.LDD(a.logger, 7, "vmHealth", "PROBE",
		"vm="+strconv.FormatInt(id, 10)+" score="+strconv.Itoa(score.Score)+" status="+score.Status)
	writeJSON(w, http.StatusOK, score)
}
