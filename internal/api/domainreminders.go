// Package api — domain reminder list endpoints (multiple reminders per event).
//
// region MODULE_CONTRACT [DOMAIN(8): Alerting; CONCEPT(7]: DomainReminders; TECH(8]: net/http]
// @purpose Feed the per-domain reminder list UI: list / add / delete reminders.
//
// @io GET /api/domains/{id}/reminders ; POST /api/domains/{id}/reminders ; DELETE /api/reminders/{id}
// @invariants
//   - days is validated server-side too (cert/owner need days>0; dns ignores it).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: domain reminders, list, add, delete, cert, owner, dns
package api

import (
	"net/http"
	"strconv"

	"github.com/skibine/vmp/internal/store"
)

func registerDomainReminders(mux *http.ServeMux, a *crudAPI) {
	mux.HandleFunc("GET /api/domains/{id}/reminders", a.listDomainReminders)
	mux.HandleFunc("POST /api/domains/{id}/reminders", a.createDomainReminder)
	mux.HandleFunc("DELETE /api/reminders/{rid}", a.deleteDomainReminder)
}

// region FUNC_listDomainReminders [DOMAIN(7): Alerting; CONCEPT(6]: Read; TECH(5]: net/http]
// @purpose Return all reminders for one domain.
// @complexity 3
// endregion FUNC_listDomainReminders
func (a *crudAPI) listDomainReminders(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	rs, err := a.st.ListDomainReminders(r.Context(), id)
	if err != nil {
		a.writeErr(w, "listDomainReminders", err)
		return
	}
	if rs == nil {
		rs = []store.DomainReminder{}
	}
	writeJSON(w, http.StatusOK, rs)
}

// region FUNC_createDomainReminder [DOMAIN(7): Alerting; CONCEPT(6]: Create; TECH(5]: net/http]
// @purpose Add a reminder (kind/days/channel_id/repeat_days).
// @complexity 4
// endregion FUNC_createDomainReminder
func (a *crudAPI) createDomainReminder(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var rem store.DomainReminder
	if !readJSON(w, r, &rem) {
		return
	}
	rem.DomainID = id
	rid, err := a.st.CreateDomainReminder(r.Context(), rem)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	rem.ID = rid
	writeJSON(w, http.StatusCreated, rem)
}

// region FUNC_deleteDomainReminder [DOMAIN(7): Alerting; CONCEPT(6]: Delete; TECH(5]: net/http]
// @purpose Delete a reminder by id.
// @complexity 3
// endregion FUNC_deleteDomainReminder
func (a *crudAPI) deleteDomainReminder(w http.ResponseWriter, r *http.Request) {
	rid, err := strconv.ParseInt(r.PathValue("rid"), 10, 64)
	if err != nil || rid <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	if err := a.st.DeleteDomainReminder(r.Context(), rid); err != nil {
		a.writeErr(w, "deleteDomainReminder", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}
