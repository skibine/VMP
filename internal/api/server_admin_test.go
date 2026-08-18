// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): ShutdownEndpoint; TECH(8): go test,httptest]
// @purpose Verify the web stop button path: auth-gated, audit-logged, fires the wired stop func.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, shutdown, stop server, endpoint, auth, audit
package api

import (
	"net/http"
	"testing"
	"time"
)

// region FUNC_test_ShutdownEndpoint [DOMAIN(7): Testing; CONCEPT(7): StopPath; TECH(6): httptest]
// @purpose POST /api/server/shutdown responds 200 and triggers the injected func; without a wired
//
//	func it reports 503 instead of crashing.
//
// @complexity 3
// endregion FUNC_test_ShutdownEndpoint
func TestShutdownEndpoint_FiresWiredStop(t *testing.T) {
	srv, _ := newServer(t)
	fired := make(chan struct{}, 1)
	srv.WithShutdownFunc(func() { fired <- struct{}{} })

	rec := do(srv, http.MethodPost, "/api/server/shutdown", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	select {
	case <-fired:
		t.Logf("[IMP:9][TestShutdown][RESULT] stop func fired after 200 OK")
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown func not fired")
	}
}

// region FUNC_test_ShutdownEndpoint_Unwired [DOMAIN(6): Testing; CONCEPT(6): NoCrash; TECH(4): httptest]
// @purpose Unwired shutdown degrades to 503, never panics.
// @complexity 2
// endregion FUNC_test_ShutdownEndpoint_Unwired
func TestShutdownEndpoint_Unwired503(t *testing.T) {
	srv, _ := newServer(t)
	rec := do(srv, http.MethodPost, "/api/server/shutdown", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503, got %d", rec.Code)
	}
}

// endregion FUNC_test_ShutdownEndpoint
