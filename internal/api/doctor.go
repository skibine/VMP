// Package api — login-page host audit (doctor over HTTP).
//
// region MODULE_CONTRACT [DOMAIN(8): Ops; CONCEPT(7): HostAudit; TECH(7): net/http]
// @purpose Let the operator run the doctor self-audit from the LOGIN page (no console needed -
//
//	the whole point for windowsgui builds where `vmpulse doctor` prints nothing).
//
// @invariants
//   - PUBLIC endpoint, but LOCAL MODE ONLY: the report (open ports, sshd posture, public IP/ASN)
//     is host-recon material - serving it unauthenticated on a server-mode instance would leak
//     posture to anyone who can reach the port. Server mode answers 403 with a CLI hint.
//   - Read-only: audit collects facts, changes nothing.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: doctor, host audit, login, public endpoint, local mode, posture, json report
// STRUCTURE: ▶ GET /api/doctor → ◇ server-mode? ⎋403 → ⚡ Audit(45s) → ⊕ json → ⎷ 200
package api

import (
	"context"
	"net/http"
	"time"

	"github.com/skibine/vmp/internal/install"
	"github.com/skibine/vmp/internal/logging"
)

// handleDoctorPublic runs the read-only host audit and returns the JSON report.
func (s *Server) handleDoctorPublic(w http.ResponseWriter, r *http.Request) {
	if s.deployMode == "server" {
		logging.LDD(s.logger, 9, "doctor", "DENIED", "server-mode: run `vmpulse doctor` in a terminal")
		writeJSON(w, http.StatusForbidden, map[string]string{
			"error": "host audit is disabled on server-mode instances - run `vmpulse doctor` in a terminal",
		})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	rep := install.Audit(ctx, s.logger)
	b, err := install.MarshalJSONReport(rep)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "marshal: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}
