// Package api — AI action approval endpoints (Plane B). The model proposes; the operator approves.
//
// region MODULE_CONTRACT [DOMAIN(9): API,Security; CONCEPT(8): ActionApproval; TECH(8): net/http,ssh]
// @purpose Expose pending AI actions for the UI and execute approved ones over SSH (audit-logged).
// @invariants
//   - Execution only happens on the approve path, after the operator's explicit click.
//   - Every execution writes a tamper-evident audit entry (ai_action_run).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: ai actions, approve, reject, pending, execute, audit, mutating, plane b
// STRUCTURE: ▶ GET pending → ⊕ JSON ; approve → ◇ dial → ⚡ RunCommand → ⊕ output → ⚡ audit → ⎋
package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/skibine/vm-pulse/internal/audit"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// registerAIActions wires the action approval endpoints onto a crudAPI (which carries the dialer).
func registerAIActions(mux *http.ServeMux, a *crudAPI) {
	mux.HandleFunc("GET /api/ai/actions", a.listAIActions)
	mux.HandleFunc("POST /api/ai/actions/{id}/approve", a.approveAIAction)
	mux.HandleFunc("POST /api/ai/actions/{id}/reject", a.rejectAIAction)
}

// listAIActions returns actions (optionally ?status=pending), newest first.
func (a *crudAPI) listAIActions(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	out, err := a.st.ListAIActions(r.Context(), status)
	if err != nil {
		a.writeErr(w, "listAIActions", err)
		return
	}
	if out == nil {
		out = []store.AIAction{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"actions": out})
}

// approveAIAction executes an approved action over SSH and records the outcome + audit entry.
func (a *crudAPI) approveAIAction(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	act, err := a.st.GetAIAction(r.Context(), id)
	if err != nil {
		a.writeErr(w, "approveAIAction", err)
		return
	}
	if act.Status != "pending" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "action is not pending (status=" + act.Status + ")"})
		return
	}
	client, _, derr := a.dialer.Dial(r.Context(), act.VMID)
	if derr != nil {
		_ = a.st.SetAIActionStatus(r.Context(), id, "error", "dial failed: "+derr.Error())
		writeJSON(w, http.StatusOK, map[string]any{"status": "error", "error": classifyDialKind(derr), "detail": derr.Error()})
		return
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	out, runErr := a.dialer.RunCommand(ctx, client, act.Command)
	status := "done"
	if runErr != nil {
		status = "error"
	}
	_ = a.st.SetAIActionStatus(r.Context(), id, status, out+"\n"+errText(runErr))
	logging.LDD(a.logger, 9, "approveAIAction", "EXECUTED",
		"vm="+strconv.FormatInt(act.VMID, 10)+" cmd="+act.Command[:min(80, len(act.Command))])
	_ = audit.Append(a.st.DB, a.logger, audit.Entry{
		Plane: audit.PlaneB, Action: "ai_action_run", Success: status == "done",
		Detail: "action=" + strconv.FormatInt(id, 10) + " vm=" + strconv.FormatInt(act.VMID, 10) + " cmd=" + act.Command,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "output": out, "error": errText(runErr)})
}

// rejectAIAction marks a pending action rejected without executing.
func (a *crudAPI) rejectAIAction(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	act, err := a.st.GetAIAction(r.Context(), id)
	if err != nil {
		a.writeErr(w, "rejectAIAction", err)
		return
	}
	if act.Status != "pending" {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "action is not pending"})
		return
	}
	_ = a.st.SetAIActionStatus(r.Context(), id, "rejected", "")
	writeJSON(w, http.StatusOK, map[string]string{"status": "rejected"})
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
