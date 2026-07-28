// Package api — on-demand diagnostics and "run now" for checks.
//
// region MODULE_CONTRACT [DOMAIN(8): API; CONCEPT(7): Diagnostics; TECH(8): net/http,monitor]
// @purpose Run a probe immediately. diagnose = ad-hoc (NOT stored); run-now = execute a scheduled
//
//	check now and persist its result.
//
// @invariants
//   - diagnose never writes to check_results (one-shot diagnostics).
//   - Both reuse the monitor checker implementations (Plane A: no credentials).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: diagnose, run now, probe, ping, tcp, http, tls, whois, ad-hoc
// STRUCTURE: ▶ ┌vm/check┐ → ○ resolve target → ⚡ checker.Run → ⊕ Result JSON → ⎷
package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/monitor"
)

// registerDiagnostics wires the on-demand endpoints.
func registerDiagnostics(mux *http.ServeMux, a *crudAPI) {
	mux.HandleFunc("POST /api/vms/{id}/diagnose", a.diagnoseVM)
	mux.HandleFunc("GET /api/vms/{id}/battery", a.batteryVM)
	mux.HandleFunc("GET /api/vms/{id}/portscan", a.portScanVM)
	mux.HandleFunc("POST /api/vms/{id}/deepscan", a.deepScanVM)
	mux.HandleFunc("GET /api/vms/{id}/exposures", a.exposuresVM)
	mux.HandleFunc("POST /api/exposures/scan-all", a.exposuresScanAll)
	mux.HandleFunc("GET /api/vms/{id}/ipinfo", a.ipInfoVM)
	mux.HandleFunc("GET /api/vms/{id}/errors", a.errorsVM)
	mux.HandleFunc("GET /api/vms/{id}/updates", a.updatesVM)
	mux.HandleFunc("GET /api/vms/{id}/vhosts", a.vhostsVM)
	mux.HandleFunc("GET /api/vms/{id}/siteinfo", a.siteInfoVM)
	mux.HandleFunc("GET /api/domains/{id}/info", a.domainInfo)
	mux.HandleFunc("POST /api/checks/{id}/run", a.runCheckNow)
}

// diagnoseVM runs an ad-hoc probe against the VM (not persisted).
func (a *crudAPI) diagnoseVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var body struct {
		CheckType string         `json:"check_type"`
		Params    map[string]any `json:"params"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.CheckType == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "check_type required"})
		return
	}
	vm, err := a.st.GetVM(r.Context(), id)
	if err != nil {
		a.writeErr(w, "diagnoseVM", err)
		return
	}
	target := vm.IP
	if target == "" {
		target = vm.Hostname
	}
	// DNS is more meaningful against the hostname (resolve name -> IP); other probes use the IP.
	if body.CheckType == "dns" && vm.Hostname != "" {
		target = vm.Hostname
	}
	reg := monitor.DefaultRegistry()
	res, err := monitor.RunProbe(r.Context(), reg, body.CheckType, target, body.Params)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": string(res.Status), "latency_ms": res.LatencyMS, "message": res.Message, "detail": res.Detail,
	})
}

// batteryVM runs the fixed credential-less probe battery (ssh/dns/web/tls) in parallel and
// returns the reachability summary. Auto-run by the UI on VM select (Plane A liveness).
func (a *crudAPI) batteryVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	vm, err := a.st.GetVM(r.Context(), id)
	if err != nil {
		a.writeErr(w, "batteryVM", err)
		return
	}
	reg := monitor.DefaultRegistry()
	outcomes := monitor.Battery(r.Context(), reg, vm, 6*time.Second)
	writeJSON(w, http.StatusOK, monitor.Summarize(outcomes))
}

// portScanVM scans common TCP ports from the VM Pulse host (Plane A; no credentials) and reports
// which face the internet.
func (a *crudAPI) portScanVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	vm, err := a.st.GetVM(r.Context(), id)
	if err != nil {
		a.writeErr(w, "portScanVM", err)
		return
	}
	host := vm.IP
	if host == "" {
		host = vm.Hostname
	}
	ports := monitor.PortScan(r.Context(), host, 8*time.Second)
	writeJSON(w, http.StatusOK, map[string]any{"host": host, "ports": ports})
}

// deepScanVM runs a wide TCP port scan (fast ~1k ports, or full 1-65535) to find non-standard
// open ports the fixed common-port scan misses. Plane A (no creds). Bounded to 4 min so a slow
// network can't hang it forever; the request context (UI abort) also cancels mid-scan.
func (a *crudAPI) deepScanVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	vm, err := a.st.GetVM(r.Context(), id)
	if err != nil {
		a.writeErr(w, "deepScanVM", err)
		return
	}
	host := vm.IP
	if host == "" {
		host = vm.Hostname
	}
	scope := r.URL.Query().Get("scope")
	if scope != "full" {
		scope = "fast"
	}
	ctx, cancel := context.WithTimeout(r.Context(), 4*time.Minute)
	defer cancel()
	logging.LDD(a.logger, 8, "deepScanVM", "START", fmt.Sprintf("host=%s scope=%s", host, scope))
	start := time.Now()
	open := monitor.DeepScan(ctx, host, scope, 1200*time.Millisecond)
	logging.LDD(a.logger, 8, "deepScanVM", "DONE", fmt.Sprintf("host=%s open=%d elapsed=%s", host, len(open), time.Since(start).Round(time.Millisecond)))
	writeJSON(w, http.StatusOK, map[string]any{"host": host, "scope": scope, "open": open, "count": len(open)})
}

// exposuresVM runs the curated exposure scan (protocol-aware, credential-free) against the VM's
// public IP — confirms exploitable exposure (Redis +PONG, Docker /version, .git/.env, weak TLS...).
func (a *crudAPI) exposuresVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	vm, err := a.st.GetVM(r.Context(), id)
	if err != nil {
		a.writeErr(w, "exposuresVM", err)
		return
	}
	host := vm.IP
	if host == "" {
		host = vm.Hostname
	}
	if host == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "vm has no host/IP to scan"})
		return
	}
	findings := monitor.Exposures(r.Context(), host, 12*time.Second)
	v := monitor.ExposuresVerdict(findings)
	// Persist + propagate to ALL VMs sharing this host (target = ip/hostname). Probing the same host
	// yields the same result, so scanning one VM on a shared host clears the alert for the rest too —
	// not just the viewed VM. exceptVMID=0 so the source VM is updated as well.
	a.st.PropagateExposuresResult(r.Context(), 0, host, string(v.Status), v.Message, v.Detail)
	writeJSON(w, http.StatusOK, map[string]any{"host": host, "findings": findings})
}

// exposuresScanAll re-scans exposures for every unique host in the fleet and propagates each result
// to all VMs on that host. Use after fixing a server-wide issue: one click clears stale alerts
// fleet-wide instead of waiting for each VM's periodic cycle (or opening each one).
func (a *crudAPI) exposuresScanAll(w http.ResponseWriter, r *http.Request) {
	vms, err := a.st.ListVMs(r.Context(), false)
	if err != nil {
		a.writeErr(w, "exposuresScanAll", err)
		return
	}
	// Deduplicate by scan target (ip, falling back to hostname) — one probe per host, not per VM.
	seen := map[string]bool{}
	var hosts []string
	for _, vm := range vms {
		t := vm.IP
		if t == "" {
			t = vm.Hostname
		}
		if t == "" || seen[t] {
			continue
		}
		seen[t] = true
		hosts = append(hosts, t)
	}
	ctx := r.Context()
	totalFindings := 0
	for _, host := range hosts {
		findings := monitor.Exposures(ctx, host, 12*time.Second)
		v := monitor.ExposuresVerdict(findings)
		a.st.PropagateExposuresResult(ctx, 0, host, string(v.Status), v.Message, v.Detail)
		totalFindings += len(findings)
	}
	writeJSON(w, http.StatusOK, map[string]any{"hosts_scanned": len(hosts), "findings": totalFindings})
}

// ipInfoVM returns the geo/ASN/PTR info for the VM's public IP (Plane A, keyless).
func (a *crudAPI) ipInfoVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	vm, err := a.st.GetVM(r.Context(), id)
	if err != nil {
		a.writeErr(w, "ipInfoVM", err)
		return
	}
	ip := vm.IP
	if ip == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "vm has no IP; IP-info needs a public IP"})
		return
	}
	info, _ := monitor.LookupIPInfo(r.Context(), ip)
	writeJSON(w, http.StatusOK, info)
}

// errorsVM returns recent priority=err log lines over SSH (Plane B; needs creds).
func (a *crudAPI) errorsVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	window := r.URL.Query().Get("range")
	if window == "" {
		window = "24h"
	}
	client, _, derr := a.dialer.Dial(r.Context(), id)
	if derr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": classifyDialKind(derr), "detail": derr.Error()})
		return
	}
	defer client.Close()
	// Fetch the stored sudo password (if any) so a non-root SSH user with password-sudo can still
	// read the system journal via `sudo -S` (otherwise journalctl is denied and we'd see a false 0).
	var sudoPassword string
	if creds, ok, _ := a.st.GetVMCredentials(r.Context(), id); ok {
		sudoPassword = creds.SudoPassword
	}
	el, err := a.dialer.RecentErrors(r.Context(), client, window, sudoPassword)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": "other", "detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, el)
}

// vhostsVM returns the web-server virtual-host config over SSH (Plane B; needs creds).
func (a *crudAPI) vhostsVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	client, _, derr := a.dialer.Dial(r.Context(), id)
	if derr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": classifyDialKind(derr), "detail": derr.Error()})
		return
	}
	defer client.Close()
	vl, err := a.dialer.VHosts(r.Context(), client)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": "other", "detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, vl)
}

// siteInfoVM fetches HTTP response headers + security posture + CMS fingerprint for the VM's site
// (or an explicit ?url=). Plane A: a plain HTTP GET from the VM Pulse host, no SSH credentials.
func (a *crudAPI) siteInfoVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	url := r.URL.Query().Get("url")
	if url == "" {
		vm, err := a.st.GetVM(r.Context(), id)
		if err != nil {
			a.writeErr(w, "siteInfoVM", err)
			return
		}
		host := vm.IP
		if host == "" {
			host = vm.Hostname
		}
		url = "http://" + host + "/"
	}
	info, _ := monitor.ProbeSite(r.Context(), url)
	writeJSON(w, http.StatusOK, info)
}

// domainInfo runs the DNS + cert + whois probe for a domain (Plane A; no credentials).
func (a *crudAPI) domainInfo(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	d, err := a.st.GetDomain(r.Context(), id)
	if err != nil {
		a.writeErr(w, "domainInfo", err)
		return
	}
	info, _ := monitor.ProbeDomain(r.Context(), d.Name)
	writeJSON(w, http.StatusOK, info)
}

// updatesVM checks for available package updates over SSH (Plane B; read-only apt-get simulate).
func (a *crudAPI) updatesVM(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	client, _, derr := a.dialer.Dial(r.Context(), id)
	if derr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": classifyDialKind(derr), "detail": derr.Error()})
		return
	}
	defer client.Close()
	u, err := a.dialer.Updates(r.Context(), client)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": "other", "detail": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, u)
}

// runCheckNow executes a scheduled check immediately and persists the result.
func (a *crudAPI) runCheckNow(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	c, err := a.st.GetCheck(r.Context(), id)
	if err != nil {
		a.writeErr(w, "runCheckNow", err)
		return
	}
	reg := monitor.DefaultRegistry()
	res, _ := monitor.ExecuteCheck(r.Context(), a.st, reg, a.logger, c)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": string(res.Status), "latency_ms": res.LatencyMS, "message": res.Message, "detail": res.Detail,
	})
}
