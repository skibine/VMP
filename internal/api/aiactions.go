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
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/skibine/vmp/internal/audit"
	"github.com/skibine/vmp/internal/logging"
	"github.com/skibine/vmp/internal/store"
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
// HTTP face of executeApprovedAction (the Telegram bridge calls the same path via ApproveAIAction).
func (a *crudAPI) approveAIAction(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	status, out, rerr := a.executeApprovedAction(r.Context(), id, "web")
	if rerr != nil {
		var np *notPendingError
		if errors.As(rerr, &np) {
			writeJSON(w, http.StatusConflict, map[string]string{"error": np.Error()})
			return
		}
		a.writeErr(w, "approveAIAction", rerr)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": status, "output": out, "error": statusToErr(status, out)})
}

// executeApprovedAction loads a PENDING action by id, runs it over SSH (sudo-aware), records the
// outcome and writes the tamper-evident audit entry. Shared by the web approve button and the
// Telegram ✅ callback — the ONLY two doors into command execution. `via` labels the origin in the
// audit chain ("web" | "telegram").
func (a *crudAPI) executeApprovedAction(ctx context.Context, id int64, via string) (status, output string, rerr error) {
	act, err := a.st.GetAIAction(ctx, id)
	if err != nil {
		return "", "", err
	}
	if act.Status != "pending" {
		return act.Status, act.Output, errNotPending(act.Status)
	}
	client, _, derr := a.dialer.Dial(ctx, act.VMID)
	if derr != nil {
		_ = a.st.SetAIActionStatus(ctx, id, "error", "dial failed: "+derr.Error())
		logging.LDD(a.logger, 9, "approveAIAction", "DIAL_FAIL", "vm="+strconv.FormatInt(act.VMID, 10)+" "+classifyDialKind(derr))
		_ = audit.Append(a.st.DB, a.logger, audit.Entry{
			Plane: audit.PlaneB, Action: "ai_action_run", Success: false,
			Detail: "action=" + strconv.FormatInt(id, 10) + " vm=" + strconv.FormatInt(act.VMID, 10) +
				" cmd=" + act.Command + " via=" + via + " dial_failed=" + classifyDialKind(derr),
		})
		return "error", "dial failed: " + derr.Error(), nil
	}
	defer client.Close()
	// Fetch the stored sudo password (if any) so privileged commands (install/restart/...) run via
	// `sudo -S` instead of failing on a non-interactive password prompt.
	var sudoPassword string
	if creds, ok, _ := a.st.GetVMCredentials(ctx, act.VMID); ok {
		sudoPassword = creds.SudoPassword
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	out, runErr := a.dialer.RunCommand(rctx, client, act.Command, sudoPassword)
	status = "done"
	if runErr != nil {
		status = "error"
	}
	_ = a.st.SetAIActionStatus(ctx, id, status, out+"\n"+errText(runErr))
	logging.LDD(a.logger, 9, "approveAIAction", "EXECUTED",
		"vm="+strconv.FormatInt(act.VMID, 10)+" cmd="+act.Command[:min(80, len(act.Command))]+" via="+via)
	_ = audit.Append(a.st.DB, a.logger, audit.Entry{
		Plane: audit.PlaneB, Action: "ai_action_run", Success: status == "done",
		Detail: "action=" + strconv.FormatInt(id, 10) + " vm=" + strconv.FormatInt(act.VMID, 10) +
			" cmd=" + act.Command + " via=" + via,
	})
	return status, out, nil
}

// errNotPending marks an approve attempt on an action that is no longer pending (double-click /
// stale Telegram callback). The current status travels out so callers can show it.
type notPendingError struct{ status string }

func (e *notPendingError) Error() string { return "action is not pending (status=" + e.status + ")" }

func errNotPending(status string) error { return &notPendingError{status: status} }

// statusToErr renders the HTTP error field "" on success (kept for response-shape compatibility).
func statusToErr(status, out string) string {
	if status == "done" {
		return ""
	}
	return out
}

// ApproveAIAction executes a pending AI action from OUTSIDE the HTTP stack (the Telegram bridge).
// Returns (status, output, error); status is "done" | "error" — a dial/run failure is reported as
// status="error" with a nil Go error (the action itself resolved), while infra errors (db) are
// returned as Go errors. Idempotency: a non-pending action yields a notPendingError.
func (s *Server) ApproveAIAction(ctx context.Context, id int64, via string) (status, output string, err error) {
	return s.crud.executeApprovedAction(ctx, id, via)
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
