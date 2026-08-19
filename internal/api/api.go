// Package api exposes the VM Pulse HTTP surface (REST + future WebSocket).
//
// region MODULE_CONTRACT [DOMAIN(7): API; CONCEPT(8): HTTPServer; TECH(9): net/http]
// @purpose Serve agent-friendly HTTP endpoints with graceful shutdown. The scaffold ships
//
//	/healthz; future slices add CRUD, web-SSH, and AI/MCP tooling. Plane A monitoring
//	and Plane B management both ride this server but enforce their own gating.
//
// @io (store *store.Store, addr string, logger) -> *Server
// @uses net/http, encoding/json, context, github.com/skibine/vmp/internal/store
// @invariants
//   - New NEVER returns a nil mux.
//   - /healthz never requires authentication (it reports liveness only, no secrets).
//   - Serve blocks until ctx is cancelled, then shuts down within the shutdown timeout.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: http, server, healthz, graceful, shutdown, mux, api, liveness
// STRUCTURE: ▶ ┌store+addr┐ → ○ NewServeMux → ⊕ /healthz → ⚡ ListenAndServe ⟂ ctx → ⎋ Shutdown
package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/skibine/vmp/internal/ai"
	"github.com/skibine/vmp/internal/auth"
	"github.com/skibine/vmp/internal/logging"
	"github.com/skibine/vmp/internal/store"
)

// shutdownTimeout bounds graceful shutdown.
const shutdownTimeout = 5 * time.Second

// Version is the build version stamp. Default "dev"; the release Makefile injects the real value
// via -ldflags "-X 'main.Version=...'" (which main copies into this package var before New()).
var Version = "dev"

// region STRUCT_Server [DOMAIN(7): API; CONCEPT(7): Server; TECH(8): net/http]
// @purpose Bind an *http.Server to the store and expose its mux for testing (httptest).
// endregion STRUCT_Server
type Server struct {
	store        *store.Store
	logger       *slog.Logger
	srv          *http.Server
	mux          *http.ServeMux
	agent        *ai.Agent          // nil when AI is not configured (chat endpoint -> 503)
	pending2FA   *auth.PendingTwoFA // in-memory bridge for two-step 2FA login
	loginLimiter *auth.Limiter      // brute-force damper: ip+username sliding window
	ipLimiter    *auth.Limiter      // argon2-DoS damper: per-IP cap across ALL usernames
	deployMode   string             // config mode ("local"|"server") - drives the UI security banner
	chatMirror   ChatMirror         // optional web->telegram chat relay
	shutdownFn   func()             // graceful-stop trigger (main wires it to the signal ctx cancel)
	crud         *crudAPI           // owns the domain-health cache + warmer loop
	Version      string             // build version stamp (injected via -ldflags main.Version), "dev" if unset
}

// WithAgent attaches an AI agent (enables POST /api/ai/chat).
func (s *Server) WithAgent(a *ai.Agent) *Server { s.agent = a; return s }

// ChatMirror relays completed WEB chat turns to an external frontend (the Telegram bridge).
// Optional: without one the web chat works exactly as before (setups without telegram).
type ChatMirror interface {
	// actionWatermark is the max ai_action id BEFORE the turn; the mirror uses it to surface
	// only the pending actions this turn created (with approve buttons where supported).
	MirrorWebTurn(ctx context.Context, user, assistant string, actionWatermark int64)
}

// WithChatMirror attaches the web->telegram relay (no-op when never called).
func (s *Server) WithChatMirror(m ChatMirror) *Server { s.chatMirror = m; return s }

// Use wraps the mux with middleware (e.g. auth). Called after New in production wiring.
// Tests build the server without Use, so they exercise routes unauthenticated.
func (s *Server) Use(mw func(http.Handler) http.Handler) {
	if s.srv != nil {
		// securityHeaders wraps OUTERMOST: hardening applies to API and SPA alike.
		s.srv.Handler = securityHeaders(mw(s.mux))
	}
}

// region FUNC_New [DOMAIN(7): API; CONCEPT(7): Build; TECH(7): net/http]
// @purpose Construct a Server with all routes wired. The returned Handler() can be driven
//
//	directly by httptest without binding a real port.
//
// @complexity 3
// endregion FUNC_New
func New(s *store.Store, addr string, logger *slog.Logger) *Server {
	mux := http.NewServeMux()
	srv := &Server{store: s, logger: logger, mux: mux, pending2FA: auth.NewPendingTwoFA(),
		loginLimiter: auth.NewLimiter(loginMaxAttempts, loginWindow),
		ipLimiter:    auth.NewLimiter(loginIPMaxAttempts, loginWindow), Version: Version}
	mux.HandleFunc("/healthz", srv.healthHandler)
	mux.HandleFunc("GET /api/security/status", srv.securityStatus) // auth-gated (not in public list)
	// Public build-version endpoint (no auth) so the login page + header can show the version stamp
	// for build-mismatch debugging (sandbox vs operator PC).
	mux.HandleFunc("/api/version", srv.versionHandler)
	mux.HandleFunc("GET /api/doctor", srv.handleDoctorPublic) // login-page host audit (local mode only; gated inside)
	mux.HandleFunc("POST /api/auth/login", srv.login)
	mux.HandleFunc("POST /api/auth/login/2fa", srv.loginTwoFA)
	mux.HandleFunc("POST /api/auth/logout", srv.logout)
	mux.HandleFunc("GET /api/auth/me", srv.me)
	mux.HandleFunc("GET /api/auth/2fa/status", srv.twoFAStatus)
	mux.HandleFunc("POST /api/auth/2fa/setup", srv.twoFASetup)
	mux.HandleFunc("POST /api/auth/2fa/enable", srv.twoFAEnable)
	mux.HandleFunc("POST /api/auth/2fa/disable", srv.twoFADisable)
	mux.HandleFunc("PUT /api/auth/password", srv.changePassword)
	mux.HandleFunc("POST /api/server/shutdown", srv.handleShutdown) // Plane B: graceful stop from the UI
	mux.HandleFunc("POST /api/ai/chat", srv.aiChat)                 // TODO(auth): gate in Plane B session middleware
	mux.HandleFunc("GET /api/ai/history", srv.aiHistory)
	mux.HandleFunc("DELETE /api/ai/history", srv.aiHistoryClear)
	srv.crud = RegisterCRUD(mux, s, logger) // TODO(auth): wrap CRUD routes with Plane B session middleware
	registerWebSSH(mux, s, logger)          // Plane B: web-ssh terminal + snapshot + hostkey reset
	registerMetrics(mux, s, logger)         // Plane A: metrics series + pull-poller toggle
	registerSPA(mux)                        // catch-all "/" serves the embedded frontend
	srv.srv = &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return srv
}

// Handler returns the configured mux (for httptest / embedding).
func (s *Server) Handler() http.Handler { return s.mux }

// region FUNC_healthHandler [DOMAIN(7): API; CONCEPT(6): Liveness; TECH(6): net/http]
// @purpose Report process liveness + DB readiness + schema version. Stateless and public.
// @complexity 3
// endregion FUNC_healthHandler
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ver, err := s.store.LatestVersion()
	dbOK := err == nil && ver >= 1
	status := "ok"
	if !dbOK {
		status = "degraded"
	}
	logging.LDD(s.logger, 7, "healthHandler", "PROBE", status)
	// BUG_FIX_CONTEXT (audit round 2): WriteHeader came AFTER Encode - Go implicitly sends
	// 200 once the first body byte is written, so the 503 never reached clients (load
	// balancers kept routing to a degraded instance).
	if !dbOK {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":         status,
		"db":             dbOK,
		"schema_version": ver,
	})
}

// versionHandler returns the build version stamp. Public (no auth) so the SPA/login page can show it
// for build-mismatch debugging between environments.
func (s *Server) versionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"version": s.Version})
}

// region FUNC_Serve [DOMAIN(7): API; CONCEPT(8): Lifecycle; TECH(8): net/http]
// @purpose Run the HTTP server until ctx is cancelled, then shut down gracefully. Blocks.
// @complexity 5
// @invariants
//   - On fatal ListenAndServe error (other than closed at shutdown) it is returned.
//
// endregion FUNC_Serve
func (s *Server) Serve(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		logging.LDD(s.logger, 9, "Serve", "LISTENING", s.srv.Addr)
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	// Background domain-health warmer: keeps the fleet lamps warm in-memory so a fleet load never
	// blocks on a per-domain probe (DNS+TLS+whois/RDAP is seconds each). Stops with ctx.
	if s.crud != nil {
		go s.crud.warmLoop(ctx)
	}
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logging.LDD(s.logger, 8, "Serve", "SHUTDOWN", "context cancelled, draining")
		shCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		return s.srv.Shutdown(shCtx)
	}
}
