// Package api — security headers + vault exposure for the UI.
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(7): HTTPHardening; TECH(7): net/http]
// @purpose Baseline browser hardening for every response: clickjacking (X-Frame-Options/CSP
//
//	frame-ancestors), MIME sniffing, referrer leakage, and API response caching. Plus the
//	deployment security status the UI renders as a banner (vault plaintext warning).
//
// @invariants
//   - Headers apply to ALL routes (API + SPA); CSP allows only same-origin resources and
//     inline styles (Svelte component styles), and websocket upgrades to self.
//   - /api/ responses are never cached (tokens/data must not live in shared caches).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: security headers, csp, x-frame-options, nosniff, no-store, vault status, banner
// STRUCTURE: ▶ middleware: ⊕ headers → next ; GET /api/security/status → ◇ vaultArmed?mode → ⎷ json
package api

import (
	"net/http"
	"strings"
)

// region FUNC_securityHeaders [DOMAIN(9): Security; CONCEPT(7): Headers; TECH(6): middleware]
// @purpose Set the baseline hardening headers on every response.
// @complexity 2
// endregion FUNC_securityHeaders
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		// frame-ancestors duplicates X-Frame-Options for modern browsers; style-src needs
		// 'unsafe-inline' for Svelte's injected component styles; connect allows the SPA's
		// fetch + websocket calls to self only.
		// BUG_FIX_CONTEXT (audit round 2): connect-src used to list ws: wss: http: https: which
		// is scheme-any-host - no restriction at all. The SPA is same-origin; ws/wss schemes
		// still need naming (browsers do not fold them into 'self').
		h.Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self'; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

// region FUNC_Server_securityStatus [DOMAIN(9): Security; CONCEPT(7): Exposure; TECH(5): handler]
// @purpose Tell the UI whether secrets are stored PLAINTEXT (vault unarmed) so it can render a
//
//	persistent warning banner in server mode (audit 2.4: plaintext default is dangerous).
//
// @complexity 2
// endregion FUNC_Server_securityStatus
func (s *Server) securityStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":        s.deployMode,
		"vault_armed": s.store.VaultArmed(),
		"tls":         false, // vmpulse terminates TLS at a reverse proxy; the app itself is plain HTTP
	})
}

// WithDeployMode records how the instance is deployed (server mode + unarmed vault = banner).
func (s *Server) WithDeployMode(mode string) *Server { s.deployMode = mode; return s }
