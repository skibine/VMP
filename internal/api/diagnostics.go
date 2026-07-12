// Package api — on-demand diagnostics and "run now" for checks.
//
// region MODULE_CONTRACT [DOMAIN(8): API; CONCEPT(7): Diagnostics; TECH(8): net/http,monitor]
// @purpose Run a probe immediately. diagnose = ad-hoc (NOT stored); run-now = execute a scheduled
//
//	check now and persist its result.
//
// @invariants
//   - diagnose never writes to check_results (one-shot diagnostics).
//   - Both reuse the monitor checker implementations (Plane A: no credentials).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: diagnose, run now, probe, ping, tcp, http, tls, whois, ad-hoc
// STRUCTURE: ▶ ┌vm/check┐ → ○ resolve target → ⚡ checker.Run → ⊕ Result JSON → ⎷
package api

import (
	"net/http"

	"github.com/skibine/vm-pulse/internal/monitor"
)

// registerDiagnostics wires the on-demand endpoints.
func registerDiagnostics(mux *http.ServeMux, a *crudAPI) {
	mux.HandleFunc("POST /api/vms/{id}/diagnose", a.diagnoseVM)
	mux.HandleFunc("POST /api/checks/{id}/run", a.runCheckNow)
}

// diagnoseVM runs an ad-hoc probe against the VM (not persisted).
func (a *crudAPI) diagnoseVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var body struct {
		CheckType string         `json:"check_type"`
		Params    map[string]any `json:"params"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.CheckType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "check_type required"})
		return
	}
	vm, err := a.st.GetVM(r.Context(), id)
	if err != nil {
		a.writeErr(w, "diagnoseVM", err)
		return
	}
	target := vm.IP
	if target == "" {
		target = vm.Hostname
	}
	reg := monitor.DefaultRegistry()
	res, err := monitor.RunProbe(r.Context(), reg, body.CheckType, target, body.Params)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": string(res.Status), "latency_ms": res.LatencyMS, "message": res.Message, "detail": res.Detail,
	})
}

// runCheckNow executes a scheduled check immediately and persists the result.
func (a *crudAPI) runCheckNow(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := a.st.GetCheck(r.Context(), id)
	if err != nil {
		a.writeErr(w, "runCheckNow", err)
		return
	}
	reg := monitor.DefaultRegistry()
	res, _ := monitor.ExecuteCheck(r.Context(), a.st, reg, a.logger, c)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": string(res.Status), "latency_ms": res.LatencyMS, "message": res.Message, "detail": res.Detail,
	})
}
