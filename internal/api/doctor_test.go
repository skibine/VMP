// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): LoginDoctor; TECH(8): go test]
// @purpose Login-page host audit: local mode serves the report JSON; server mode refuses (403).
// GREP_SUMMARY: test, doctor, login, audit, endpoint, local, server mode
package api

import (
	"net/http"
	"strings"
	"testing"
)

func TestDoctorEndpoint_LocalServes_ServerRefuses(t *testing.T) {
	srv, _ := newServer(t) // deployMode "" (local default)

	rec := do(srv, http.MethodGet, "/api/doctor", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("local mode: want 200, got %d body=%.120s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"verdict"`) {
		t.Fatal("report JSON must carry the verdict")
	}
	t.Logf("[IMP:8][TestDoctor][RESULT] local mode report served (%d bytes)", rec.Body.Len())

	srv.WithDeployMode("server")
	rec2 := do(srv, http.MethodGet, "/api/doctor", "")
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("server mode: want 403, got %d", rec2.Code)
	}
	t.Logf("[IMP:9][TestDoctor][RESULT] server mode refused (host posture does not leak)")
}
