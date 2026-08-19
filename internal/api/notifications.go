// Package api — in-app notification center endpoints.
//
// region MODULE_CONTRACT [DOMAIN(8): Alerting; CONCEPT(7]: InApp; TECH(8]: net/http]
// @purpose Feed the bell center: list recent notifications (unread first), mark one/all read.
//
// @io GET /api/notifications -> [{...}] ; POST /api/notifications/{id}/read ; POST /api/notifications/read-all
// @invariants
//   - Read-only list never mutates; read-marking is idempotent.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: notifications, bell, unread, read, center, in-app
// STRUCTURE: ▶ GET → ○ store.ListNotifications → ⎋ JSON ; POST /{id}/read → ○ MarkNotificationRead → ⎋ ok
package api

import (
	"net/http"
	"strconv"

	"github.com/skibine/vmp/internal/store"
)

// region FUNC_registerNotifications [DOMAIN(7): Alerting; CONCEPT(6): Routing; TECH(5): net/http]
// @purpose Register the notification-center routes.
// @complexity 2
// endregion FUNC_registerNotifications
func registerNotifications(mux *http.ServeMux, a *crudAPI) {
	mux.HandleFunc("GET /api/notifications", a.listNotifications)
	mux.HandleFunc("GET /api/notifications/all", a.listAllNotifications)
	mux.HandleFunc("POST /api/notifications/{id}/read", a.markNotificationRead)
	mux.HandleFunc("POST /api/notifications/read-all", a.markAllNotificationsRead)
	mux.HandleFunc("DELETE /api/notifications", a.deleteNotifications)
}

// region FUNC_listAllNotifications [DOMAIN(7): Alerting; CONCEPT(7): ReadHistory; TECH(6): net/http]
// @purpose Paged + filtered notification history for the bell modal ("show all"): ?page,
//
//	?page_size (max 200), ?kind (alert|reminder|test), ?unread=1. Returns {items,total,page,page_size}.
//	(The plain GET /api/notifications keeps its legacy array shape for the dropdown.)
//
// @complexity 4
// endregion FUNC_listAllNotifications
func (a *crudAPI) listAllNotifications(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page := max(1, atoiDefault(q.Get("page"), 1))
	size := clampInt(atoiDefault(q.Get("page_size"), 50), 1, 200)
	ns, count, err := a.st.ListNotificationsFiltered(r.Context(), store.NotificationFilter{
		UnreadOnly: q.Get("unread") == "1",
		Kind:       q.Get("kind"),
		Limit:      size, Offset: (page - 1) * size,
	})
	if err != nil {
		a.writeErr(w, "listAllNotifications", err)
		return
	}
	if ns == nil {
		ns = []store.Notification{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items": ns, "total": count, "page": page, "page_size": size,
	})
}

// region FUNC_deleteNotifications [DOMAIN(7): Alerting; CONCEPT(6): Purge; TECH(5): net/http]
// @purpose DELETE /api/notifications?scope=read|all (default read) — the modal's clear buttons.
//
//	Deleting read rows executes their one-shot reminders (same semantics as reading them).
//
// @complexity 3
// endregion FUNC_deleteNotifications
func (a *crudAPI) deleteNotifications(w http.ResponseWriter, r *http.Request) {
	all := r.URL.Query().Get("scope") == "all"
	deleted, err := a.st.DeleteNotifications(r.Context(), all)
	if err != nil {
		a.writeErr(w, "deleteNotifications", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "cleared", "deleted": deleted})
}

// region FUNC_listNotifications [DOMAIN(7): Alerting; CONCEPT(6): Read; TECH(5]: net/http]
// @purpose Return up to 30 recent notifications (unread first).
// @complexity 3
// endregion FUNC_listNotifications
func (a *crudAPI) listNotifications(w http.ResponseWriter, r *http.Request) {
	ns, err := a.st.ListNotifications(r.Context(), 30)
	if err != nil {
		a.writeErr(w, "listNotifications", err)
		return
	}
	if ns == nil {
		ns = []store.Notification{}
	}
	writeJSON(w, http.StatusOK, ns)
}

// region FUNC_markNotificationRead [DOMAIN(7): Alerting; CONCEPT(6]: Update; TECH(5]: net/http]
// @purpose Mark a single notification read.
// @complexity 3
// endregion FUNC_markNotificationRead
func (a *crudAPI) markNotificationRead(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad id"})
		return
	}
	if err := a.st.MarkNotificationRead(r.Context(), id); err != nil {
		a.writeErr(w, "markNotificationRead", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "read"})
}

// region FUNC_markAllNotificationsRead [DOMAIN(7): Alerting; CONCEPT(6]: Update; TECH(5]: net/http]
// @purpose Mark every unread notification read.
// @complexity 2
// endregion FUNC_markAllNotificationsRead
func (a *crudAPI) markAllNotificationsRead(w http.ResponseWriter, r *http.Request) {
	if err := a.st.MarkAllNotificationsRead(r.Context()); err != nil {
		a.writeErr(w, "markAllNotificationsRead", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "read"})
}
