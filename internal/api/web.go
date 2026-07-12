// Package api — SPA static serving.
//
// region MODULE_CONTRACT [DOMAIN(7): API; CONCEPT(7]: Static; TECH(8]: net/http,embed]
// @purpose Serve the embedded SPA at the catch-all "/" route with client-side routing fallback.
//
//	Registered after all /api/* routes; Go 1.22 mux precedence gives /api/* priority.
//
// @invariants
//   - Unknown non-API paths fall back to index.html (SPA client routing).
//   - The auth middleware makes non-/api/ paths public, so the login screen loads unauthenticated.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: spa, static, frontend, index.html, fallback, embed, fileserver
// STRUCTURE: ▶ ┌path┐ → ○ stat → 〈exists? serve : index.html〉 → ⎋
package api

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/skibine/vm-pulse/internal/web"
)

// registerSPA mounts the embedded frontend at "/" (catch-all).
func registerSPA(mux *http.ServeMux) {
	fsys, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		// Dist is embedded at build time; this only fails if dist is empty (frontend not built).
		return
	}
	fileServer := http.FileServer(http.FS(fsys))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		serve := "/" + p
		if p == "" {
			serve = "/"
		} else if _, statErr := fs.Stat(fsys, p); statErr != nil {
			serve = "/" // SPA fallback for client-side routes (avoid "/index.html" -> 301)
		}
		r.URL.Path = serve
		fileServer.ServeHTTP(w, r)
	})
}
