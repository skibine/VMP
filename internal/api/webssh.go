// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): WebSSH,Snapshot; TECH(8): net/http,websocket,ssh]
// @purpose Expose Plane-B SSH access over HTTP: an interactive web terminal (WebSocket) and a
//
//	one-shot metrics snapshot for a VM, plus a TOFU host-key reset. All gated by the auth
//	session middleware; credentials are resolved from the armed vault at dial time.
//
// @io registerWebSSH(mux, store, logger); routes GET /terminal, POST /snapshot, DELETE /hostkey
// @invariants
//   - Every handler requires an authenticated session (Plane B); userID is taken from context.
//   - ssh_session_open / ssh_snapshot / ssh_hostkey_reset are written to the tamper-evident audit.
//   - Dial errors are translated to machine-readable JSON/WS-close reasons for the UI.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: web-ssh, terminal, snapshot, websocket, hostkey, reset, audit, Plane B, api
// STRUCTURE: ▶ ┌{id}┐ → ○ auth ctx → ⚡ Dial(TOFU) ── err → ⊕ classify(no_creds|host_key) → ⎋ JSON/WS
package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"nhooyr.io/websocket"

	"github.com/skibine/vm-pulse/internal/audit"
	"github.com/skibine/vm-pulse/internal/auth"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/ssh"
	"github.com/skibine/vm-pulse/internal/store"
)

type websshAPI struct {
	st     *store.Store
	dialer *ssh.Dialer
	logger *slog.Logger
}

// registerWebSSH attaches the Plane-B SSH routes (terminal / snapshot / hostkey reset) to the mux.
func registerWebSSH(mux *http.ServeMux, st *store.Store, logger *slog.Logger) {
	a := &websshAPI{st: st, dialer: ssh.New(st, logger), logger: logger}
	mux.HandleFunc("GET /api/vms/{id}/terminal", a.handleTerminal)
	mux.HandleFunc("POST /api/vms/{id}/snapshot", a.handleSnapshot)
	mux.HandleFunc("DELETE /api/vms/{id}/hostkey", a.handleResetHostKey)
}

// handleTerminal upgrades to a WebSocket and bridges it to an interactive SSH PTY.
func (a *websshAPI) handleTerminal(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	userID, _ := auth.FromContext(r.Context())

	c, err := websocket.Accept(w, r, nil) // same-origin verification by default; blocks cross-origin
	if err != nil {
		logging.LDD(a.logger, 9, "handleTerminal", "ACCEPT_FAIL", err.Error())
		return
	}
	defer c.CloseNow()

	// Initial pty size from query (?rows=&cols=), sane defaults.
	rows, cols := 24, 80
	if v, err := strconv.Atoi(r.URL.Query().Get("rows")); err == nil && v > 0 {
		rows = v
	}
	if v, err := strconv.Atoi(r.URL.Query().Get("cols")); err == nil && v > 0 {
		cols = v
	}

	client, _, err := a.dialer.Dial(r.Context(), id)
	if err != nil {
		writeWSClose(c, r.Context(), classifyDialErr(err))
		return
	}
	defer client.Close()

	_ = audit.Append(a.st.DB, a.logger, audit.Entry{
		Plane: audit.PlaneB, UserID: userID, Action: "ssh_session_open",
		Detail: jsonDetail(id, rows, cols), Success: true,
	})

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if err := a.dialer.ServeTerminal(ctx, c, client, rows, cols); err != nil {
		logging.LDD(a.logger, 8, "handleTerminal", "SESSION_END", err.Error())
	}
}

// handleSnapshot runs the fixed one-shot metrics command and returns parsed CPU/RAM/disk/load.
func (a *websshAPI) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	userID, _ := auth.FromContext(r.Context())

	client, _, err := a.dialer.Dial(r.Context(), id)
	if err != nil {
		writeJSON(w, http.StatusConflict, classifyDialErr(err))
		return
	}
	defer client.Close()

	snap, err := a.dialer.Snapshot(r.Context(), client)
	if err != nil {
		logging.LDD(a.logger, 9, "handleSnapshot", "RUN_FAIL", err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "snapshot_failed", "detail": err.Error()})
		return
	}
	_ = audit.Append(a.st.DB, a.logger, audit.Entry{
		Plane: audit.PlaneB, UserID: userID, Action: "ssh_snapshot",
		Detail: jsonDetail(id), Success: true,
	})
	writeJSON(w, http.StatusOK, snap)
}

// handleResetHostKey clears the TOFU host-key entry for a VM (e.g. after a reinstall).
func (a *websshAPI) handleResetHostKey(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	userID, _ := auth.FromContext(r.Context())
	if err := a.st.DeleteHostKey(r.Context(), id); err != nil {
		logging.LDD(a.logger, 10, "resetHostKey", "ERR", err.Error())
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
		return
	}
	_ = audit.Append(a.st.DB, a.logger, audit.Entry{
		Plane: audit.PlaneB, UserID: userID, Action: "ssh_hostkey_reset",
		Detail: jsonDetail(id), Success: true,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// classifyDialErr turns a dialer error into a machine-readable reason map for the UI.
func classifyDialErr(err error) map[string]string {
	switch {
	case errors.Is(err, ssh.ErrNoCredentials):
		return map[string]string{"error": "no_ssh_credentials"}
	case errors.Is(err, ssh.ErrHostKeyChanged):
		return map[string]string{"error": "host_key_changed", "detail": err.Error()}
	default:
		return map[string]string{"error": "ssh_dial_failed", "detail": err.Error()}
	}
}

// writeWSClose sends a text JSON error to the browser before closing the WebSocket, so the UI can
// show the precise reason (no creds / host key changed / dial failed).
func writeWSClose(c *websocket.Conn, ctx context.Context, reason map[string]string) {
	if b, err := json.Marshal(reason); err == nil {
		_ = c.Write(ctx, websocket.MessageText, b)
	}
	_ = c.Close(websocket.StatusInternalError, reason["error"])
}

// jsonDetail builds a compact JSON detail string for audit entries.
func jsonDetail(id int64, extra ...int) string {
	if len(extra) >= 2 {
		b, _ := json.Marshal(map[string]int{"vm_id": int(id), "rows": extra[0], "cols": extra[1]})
		return string(b)
	}
	b, _ := json.Marshal(map[string]int{"vm_id": int(id)})
	return string(b)
}
