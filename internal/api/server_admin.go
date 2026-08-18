// Package api — server administration (graceful shutdown from the web UI).
//
// region MODULE_CONTRACT [DOMAIN(9): Ops; CONCEPT(7): Shutdown; TECH(7): net/http]
// @purpose Let the operator stop vmpulse from the Settings UI (Plane B, session-gated by the
//
//	auth middleware) — the only stop path on windowless windowsgui builds where the console
//	Ctrl+C affordance is gone. Triggers the SAME graceful drain as SIGINT/SIGTERM.
//
// @invariants
//   - The route is under /api/ => deny-by-default auth (public paths are only /healthz + login).
//   - The HTTP response is flushed BEFORE the shutdown fires (200ms grace) so the client sees 200.
//   - Every call lands in the tamper-evident audit log (Plane B).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: shutdown, stop server, graceful, settings button, windowsgui, server admin
// STRUCTURE: ▶ ┌POST /api/server/shutdown┐ → ○ auth → ⊕ audit → ⎋ 200 → ⏱ 200ms → ⚡ shutdownFn
package api

import (
	"net/http"
	"time"

	"github.com/skibine/vm-pulse/internal/audit"
	"github.com/skibine/vm-pulse/internal/auth"
	"github.com/skibine/vm-pulse/internal/logging"
)

// WithShutdownFunc attaches the graceful-stop trigger (main wires it to the signal context
// cancel — the same path Ctrl+C takes). Without one the endpoint reports 503.
func (s *Server) WithShutdownFunc(fn func()) *Server { s.shutdownFn = fn; return s }

// handleShutdown responds 200, then fires the graceful shutdown out-of-band.
func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if s.shutdownFn == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "shutdown not wired"})
		return
	}
	uid, _ := auth.FromContext(r.Context())
	_ = audit.Append(s.store.DB, s.logger, audit.Entry{
		Plane: audit.PlaneB, UserID: uid, Action: "server.shutdown",
		Detail: "via=web-ui remote=" + r.RemoteAddr, Success: true,
	})
	logging.LDD(s.logger, 9, "shutdown", "REQUESTED", "web-ui remote="+r.RemoteAddr)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "note": "shutting down"})
	go func() {
		time.Sleep(200 * time.Millisecond) // let the response flush
		s.shutdownFn()
	}()
}
