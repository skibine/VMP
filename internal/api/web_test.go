// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: SPA; TECH(8]: go test,httptest]
// @purpose Verify the embedded SPA is served at "/" and unknown non-API paths fall back to
//
//	index.html.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, spa, index.html, embed, fallback
// STRUCTURE: ▶ ┌server┐ → ○ GET / → 〈200 + app div?〉 → ⎋ assert
package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestSPA_ServesIndex(t *testing.T) {
	srv, _ := newServer(t)

	rec := do(srv, http.MethodGet, "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("/ want 200, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="app"`) {
		t.Fatalf("index.html should mount #app, got: %s", rec.Body.String())
	}

	// Unknown client route falls back to index.html (SPA routing).
	rec = do(srv, http.MethodGet, "/some/client/route", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("client route want 200 (fallback), got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), `id="app"`) {
		t.Fatalf("fallback should serve index.html")
	}
}
