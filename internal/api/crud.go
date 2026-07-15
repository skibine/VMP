// Package api — CRUD endpoints for vms / checks / domains.
//
// region MODULE_CONTRACT [DOMAIN(7): API; CONCEPT(8): CRUD; TECH(9): net/http,go1.22routing]
// @purpose Expose REST CRUD over the config model so the UI and AI tools can manage VMs,
//
//	checks and domains. NOTE: no auth gating yet — see TODO(auth); the auth slice
//	will wrap these with Plane B session middleware.
//
// @io RegisterCRUD(mux, store, logger) wires all routes.
// @uses net/http, encoding/json, github.com/skibine/vm-pulse/internal/store
// @invariants
//   - Validation errors -> 400, not found -> 404, duplicate -> 409, else -> 500.
//   - JSON only; Content-Type application/json on responses.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: CRUD, REST, vms, checks, domains, handler, json, routing
// STRUCTURE: ▶ ┌mux+store┐ → ⊕ registerCRUD → ○ handlers → 〈validate→repo→encode〉 → ⎋ JSON
package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/ssh"
	"github.com/skibine/vm-pulse/internal/store"
)

// crudAPI holds dependencies for CRUD handlers.
type crudAPI struct {
	st     *store.Store
	dialer *ssh.Dialer
	logger *slog.Logger
}

// region FUNC_RegisterCRUD [DOMAIN(7): API; CONCEPT(7): Wiring; TECH(8): go1.22routing]
// @purpose Attach all CRUD routes to the mux (Go 1.22 method+path patterns).
// @complexity 3
// endregion FUNC_RegisterCRUD
func RegisterCRUD(mux *http.ServeMux, st *store.Store, logger *slog.Logger) {
	a := &crudAPI{st: st, dialer: ssh.New(st, logger), logger: logger}

	// VMs (with soft-delete archive endpoint).
	mux.HandleFunc("GET /api/vms", a.listVMs)
	mux.HandleFunc("POST /api/vms", a.createVM)
	mux.HandleFunc("GET /api/vms/{id}", a.getVM)
	mux.HandleFunc("PUT /api/vms/{id}", a.updateVM)
	mux.HandleFunc("DELETE /api/vms/{id}", a.deleteVM)
	mux.HandleFunc("POST /api/vms/{id}/archive", a.archiveVM)

	// Read: results + K2 health-score.
	mux.HandleFunc("GET /api/vms/{id}/results", a.vmResults)
	mux.HandleFunc("GET /api/vms/{id}/health", a.vmHealth)

	// Checks.
	mux.HandleFunc("GET /api/checks", a.listChecks)
	mux.HandleFunc("POST /api/checks", a.createCheck)
	mux.HandleFunc("GET /api/checks/{id}", a.getCheck)
	mux.HandleFunc("PUT /api/checks/{id}", a.updateCheck)
	mux.HandleFunc("DELETE /api/checks/{id}", a.deleteCheck)

	// Domains.
	mux.HandleFunc("GET /api/domains", a.listDomains)
	mux.HandleFunc("POST /api/domains", a.createDomain)
	mux.HandleFunc("GET /api/domains/{id}", a.getDomain)
	mux.HandleFunc("PUT /api/domains/{id}", a.updateDomain)
	mux.HandleFunc("DELETE /api/domains/{id}", a.deleteDomain)

	// Alerts: rules, channels, fired alerts.
	registerAlerts(mux, a)

	// Settings: AI provider config + VM credentials.
	registerSettings(mux, a)

	// On-demand diagnostics + run-now.
	registerDiagnostics(mux, a)
	// AI action approval (Plane B; execute approved proposals over SSH).
	registerAIActions(mux, a)
}

// ── helpers ────────────────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return false
	}
	return true
}

// writeErr maps store/validation errors to HTTP statuses.
func (a *crudAPI) writeErr(w http.ResponseWriter, where string, err error) {
	var ve store.ValidationError
	switch {
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": ve.Error()})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	case errors.Is(err, store.ErrDuplicate):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "duplicate"})
	default:
		logging.LDD(a.logger, 10, where, "ERR", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
	}
}

func parseID(w http.ResponseWriter, r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid id"})
		return 0, false
	}
	return id, true
}

// ── VM handlers ─────────────────────────────────────────────────────────────────────

func (a *crudAPI) listVMs(w http.ResponseWriter, r *http.Request) {
	includeArchived := r.URL.Query().Has("archived")
	vms, err := a.st.ListVMs(r.Context(), includeArchived)
	if err != nil {
		a.writeErr(w, "listVMs", err)
		return
	}
	if vms == nil {
		vms = []store.VM{}
	}
	writeJSON(w, http.StatusOK, vms)
}

func (a *crudAPI) createVM(w http.ResponseWriter, r *http.Request) {
	var v store.VM
	if !readJSON(w, r, &v) {
		return
	}
	id, err := a.st.CreateVM(r.Context(), v)
	if err != nil {
		a.writeErr(w, "createVM", err)
		return
	}
	// Auto-provision the always-on system liveness check (drives the fleet dot, independent of alerts).
	port := v.PortSSH
	if port == 0 {
		port = 22
	}
	_ = a.st.EnsureSystemLiveness(r.Context(), id, port)
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (a *crudAPI) getVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	v, err := a.st.GetVM(r.Context(), id)
	if err != nil {
		a.writeErr(w, "getVM", err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func (a *crudAPI) updateVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var v store.VM
	if !readJSON(w, r, &v) {
		return
	}
	v.ID = id
	if err := a.st.UpdateVM(r.Context(), v); err != nil {
		a.writeErr(w, "updateVM", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (a *crudAPI) deleteVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := a.st.DeleteVM(r.Context(), id); err != nil {
		a.writeErr(w, "deleteVM", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *crudAPI) archiveVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := a.st.ArchiveVM(r.Context(), id); err != nil {
		a.writeErr(w, "archiveVM", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "archived"})
}

// ── Check handlers ──────────────────────────────────────────────────────────────────

func (a *crudAPI) listChecks(w http.ResponseWriter, r *http.Request) {
	var vmID *int64
	if raw := r.URL.Query().Get("vm_id"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err == nil {
			vmID = &n
		}
	}
	cs, err := a.st.ListChecks(r.Context(), vmID)
	if err != nil {
		a.writeErr(w, "listChecks", err)
		return
	}
	if cs == nil {
		cs = []store.Check{}
	}
	writeJSON(w, http.StatusOK, cs)
}

func (a *crudAPI) createCheck(w http.ResponseWriter, r *http.Request) {
	var c store.Check
	if !decodeCheck(w, r, &c) {
		return
	}
	id, err := a.st.CreateCheck(r.Context(), c)
	if err != nil {
		a.writeErr(w, "createCheck", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

// decodeCheck reads a Check JSON body and defaults Enabled=true when "enabled" is omitted
// (an omitted bool would otherwise decode to false, disabling newly created checks).
func decodeCheck(w http.ResponseWriter, r *http.Request, c *store.Check) bool {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body: " + err.Error()})
		return false
	}
	if err := json.Unmarshal(body, c); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return false
	}
	var probe map[string]any
	if json.Unmarshal(body, &probe) == nil {
		if _, ok := probe["enabled"]; !ok {
			c.Enabled = true
		}
	}
	return true
}

func (a *crudAPI) getCheck(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := a.st.GetCheck(r.Context(), id)
	if err != nil {
		a.writeErr(w, "getCheck", err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (a *crudAPI) updateCheck(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var c store.Check
	if !readJSON(w, r, &c) {
		return
	}
	c.ID = id
	if err := a.st.UpdateCheck(r.Context(), c); err != nil {
		a.writeErr(w, "updateCheck", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (a *crudAPI) deleteCheck(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := a.st.DeleteCheck(r.Context(), id); err != nil {
		a.writeErr(w, "deleteCheck", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ── Domain handlers ─────────────────────────────────────────────────────────────────

func (a *crudAPI) listDomains(w http.ResponseWriter, r *http.Request) {
	ds, err := a.st.ListDomains(r.Context())
	if err != nil {
		a.writeErr(w, "listDomains", err)
		return
	}
	if ds == nil {
		ds = []store.Domain{}
	}
	writeJSON(w, http.StatusOK, ds)
}

func (a *crudAPI) createDomain(w http.ResponseWriter, r *http.Request) {
	var d store.Domain
	if !readJSON(w, r, &d) {
		return
	}
	id, err := a.st.CreateDomain(r.Context(), d)
	if err != nil {
		a.writeErr(w, "createDomain", err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]int64{"id": id})
}

func (a *crudAPI) getDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	d, err := a.st.GetDomain(r.Context(), id)
	if err != nil {
		a.writeErr(w, "getDomain", err)
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (a *crudAPI) updateDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var d store.Domain
	if !readJSON(w, r, &d) {
		return
	}
	d.ID = id
	if err := a.st.UpdateDomain(r.Context(), d); err != nil {
		a.writeErr(w, "updateDomain", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

func (a *crudAPI) deleteDomain(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := a.st.DeleteDomain(r.Context(), id); err != nil {
		a.writeErr(w, "deleteDomain", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
