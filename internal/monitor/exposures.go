// Package monitor — security exposure scanner (Plane A, credential-free).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8]: ExposureScan; TECH(8]: net,crypto/tls]
// @purpose Confirm — not just "port open" (that's portscan) — that a service is actually
//
//	EXPOSED and exploitable without credentials: Redis answers +PONG, Docker API serves /version,
//	.git/config or .env are fetchable over HTTP, VNC/telnet face the internet, TLS is deprecated.
//	This is the nuclei "template + matcher" idea curated into pure-Go probes (no dep bloat, no
//	thousands of noisy web-app CVEs). Extensible by adding a probe function; a YAML template
//	engine can be layered on later for power users without embedding the nuclei engine.
//
// @io (ctx, host, timeout) -> []Finding
// @invariants
//   - Credential-free (Plane A): only TCP/HTTP/TLS handshakes to the target's public IP.
//   - Each probe is bounded by its own short timeout; the whole scan by an overall deadline.
//   - A finding is emitted ONLY when a protocol fingerprint confirms exposure (low false positives).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: exposures, security, redis, docker api, k8s, elasticsearch, memcached, vnc, telnet, .git, .env, weak tls, nuclei
// STRUCTURE: ▶ ┌host┐ → ∥ ∋probe: 〈fingerprint match?〉 → ⊕ []Finding → ∑ sort by severity → ⎋
package monitor

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Finding is one confirmed exposure (a protocol fingerprint matched).
type Finding struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"` // critical | high | medium
	Detail   string `json:"detail"`
}

// exposureProbe is one curated check: run against host within per-probe timeout, return a finding if exposed.
type exposureProbe func(ctx context.Context, host string) *Finding

// curatedProbes is the checked set (add here to extend — this is the "curated template library").
var curatedProbes = []exposureProbe{
	probeRedis,
	probeDockerAPI,
	probeK8sAPI,
	probeElasticsearch,
	probeMemcached,
	probeVNC,
	probeTelnet,
	probeGitExposed,
	probeEnvExposed,
	probeWeakTLS,
}

// probeTimeout bounds each individual probe; scanTimeout bounds the whole scan (passed by caller).
const probeTimeout = 3 * time.Second

// region FUNC_Exposures [DOMAIN(9): Security; CONCEPT(7]: Scan; TECH(7]: goroutines]
// @purpose Run every curated exposure probe in parallel and return the confirmed findings,
//
//	most severe first. No creds, no agent — pure external fingerprinting.
//
// @complexity 6
// endregion FUNC_Exposures
func Exposures(ctx context.Context, host string, scanTimeout time.Duration) []Finding {
	if strings.TrimSpace(host) == "" {
		return []Finding{}
	}
	bctx, cancel := context.WithTimeout(ctx, scanTimeout)
	defer cancel()

	results := make([]*Finding, len(curatedProbes))
	var wg sync.WaitGroup
	for i, p := range curatedProbes {
		wg.Add(1)
		go func(i int, p exposureProbe) {
			defer wg.Done()
			pctx, pcancel := context.WithTimeout(bctx, probeTimeout)
			defer pcancel()
			results[i] = p(pctx, host)
		}(i, p)
	}
	wg.Wait()

	out := make([]Finding, 0, len(results))
	for _, f := range results {
		if f != nil {
			out = append(out, *f)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return sevRank(out[i].Severity) < sevRank(out[j].Severity) })
	return out
}

func sevRank(s string) int {
	switch s {
	case "critical":
		return 0
	case "high":
		return 1
	default:
		return 2
	}
}

// expHTTP is the plain HTTP client used by the HTTP-based probes.
var expHTTP = &http.Client{Timeout: probeTimeout}

// expHTTPS skips cert verification: the goal is to confirm a service responds, not to trust it
// (k8s API uses self-signed cluster certs; .git/.env may sit behind https with any cert).
var expHTTPS = &http.Client{
	Timeout: probeTimeout,
	Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
}

// probeTCPAddr dials addr (host:port), optionally sends payload, and reports whether the response
// contains the expected fingerprint substring. Used by the line-protocol probes.
func probeTCPAddr(ctx context.Context, addr string, send []byte, expect string) (bool, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false, err
	}
	defer conn.Close()
	if len(send) > 0 {
		_ = conn.SetWriteDeadline(time.Now().Add(probeTimeout))
		if _, err := conn.Write(send); err != nil {
			return false, err
		}
	}
	buf := make([]byte, 512)
	_ = conn.SetReadDeadline(time.Now().Add(probeTimeout))
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		return false, err
	}
	return strings.Contains(string(buf[:n]), expect), nil
}

// region probes (each: confirm exposure via a protocol fingerprint).
// Each probe delegates to a *At helper that takes an explicit address/URL so tests can point
// them at local net listeners / httptest servers without opening privileged ports.

func probeRedis(ctx context.Context, host string) *Finding {
	return redisAt(ctx, net.JoinHostPort(host, "6379"))
}
func redisAt(ctx context.Context, addr string) *Finding {
	ok, _ := probeTCPAddr(ctx, addr, []byte("PING\r\n"), "+PONG")
	if !ok {
		return nil
	}
	return &Finding{ID: "redis-open", Severity: "critical",
		Title:  "Open Redis without auth",
		Detail: "Redis answered +PONG to an unauthenticated PING — anyone can read/write/flush your data or abuse it (crypto-miners scan this constantly)."}
}

func probeMemcached(ctx context.Context, host string) *Finding {
	return memcachedAt(ctx, net.JoinHostPort(host, "11211"))
}
func memcachedAt(ctx context.Context, addr string) *Finding {
	ok, _ := probeTCPAddr(ctx, addr, []byte("stats\r\n"), "STAT ")
	if !ok {
		return nil
	}
	return &Finding{ID: "memcached-open", Severity: "high",
		Title:  "Open Memcached without auth",
		Detail: "Memcached returned stats to an unauthenticated request — amplification-DDoS and data-leak risk."}
}

func probeVNC(ctx context.Context, host string) *Finding {
	return vncAt(ctx, net.JoinHostPort(host, "5900"))
}
func vncAt(ctx context.Context, addr string) *Finding {
	// VNC servers send the RFB protocol banner immediately on connect.
	ok, _ := probeTCPAddr(ctx, addr, nil, "RFB ")
	if !ok {
		return nil
	}
	return &Finding{ID: "vnc-open", Severity: "high",
		Title:  "VNC exposed to the internet",
		Detail: "Port :5900 sent an RFB banner — a VNC server faces the internet. Brute-force/credential-stuffing target; bind it to a VPN/SSH tunnel instead."}
}

func probeTelnet(ctx context.Context, host string) *Finding {
	return telnetAt(ctx, net.JoinHostPort(host, "23"))
}
func telnetAt(ctx context.Context, addr string) *Finding {
	// Telnet daemons open with IAC negotiation bytes (0xff followed by WILL/DO 0xfb/0xfd).
	ok, _ := probeTCPAddr(ctx, addr, nil, "\xff")
	if !ok {
		return nil
	}
	return &Finding{ID: "telnet-open", Severity: "high",
		Title:  "Telnet exposed to the internet",
		Detail: "Port :23 answered with telnet negotiation — unencrypted, credentials sniffable. Disable telnet; use SSH."}
}

func probeDockerAPI(ctx context.Context, host string) *Finding {
	return dockerAt(ctx, "http://"+host+":2375")
}
func dockerAt(ctx context.Context, baseURL string) *Finding {
	status, body, err := httpGet(ctx, expHTTP, baseURL+"/version")
	if err != nil || status != 200 || !strings.Contains(body, "Version") {
		return nil
	}
	return &Finding{ID: "docker-api-open", Severity: "critical",
		Title:  "Docker API exposed without TLS/auth",
		Detail: "The Docker daemon served /version to an unauthenticated request — full root RCE on the host (pull/run anything). Never expose :2375; use a unix socket or mTLS."}
}

func probeK8sAPI(ctx context.Context, host string) *Finding {
	return k8sAt(ctx, "https://"+host+":6443")
}
func k8sAt(ctx context.Context, baseURL string) *Finding {
	// Any HTTP response (even 401/403 from RBAC) confirms the API server is reachable from here.
	status, _, err := httpGet(ctx, expHTTPS, baseURL+"/api")
	if err != nil || status == 0 {
		return nil
	}
	return &Finding{ID: "k8s-api-open", Severity: "critical",
		Title:  "Kubernetes API server reachable",
		Detail: baseURL + "/api returned HTTP " + strconv.Itoa(status) + ". The API server faces the internet — restrict to a bastion/firewall; RBAC alone is not a perimeter."}
}

func probeElasticsearch(ctx context.Context, host string) *Finding {
	return elasticAt(ctx, "http://"+host+":9200")
}
func elasticAt(ctx context.Context, baseURL string) *Finding {
	status, body, err := httpGet(ctx, expHTTP, baseURL+"/")
	if err != nil || status != 200 {
		return nil
	}
	if !strings.Contains(body, "version") && !strings.Contains(body, "cluster_name") {
		return nil
	}
	return &Finding{ID: "elastic-open", Severity: "high",
		Title:  "Open Elasticsearch without auth",
		Detail: "Elasticsearch returned cluster info unauthenticated — full read/write of indices, common data-leak vector."}
}

// envPattern matches typical dotenv lines (KEY=value) to avoid flagging a 404 page mentioning ".env".
var envPattern = regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]{2,}=`)

func probeGitExposed(ctx context.Context, host string) *Finding {
	return gitHTTPAt(ctx, host, []string{"http", "https"})
}
func gitHTTPAt(ctx context.Context, host string, schemes []string) *Finding {
	for _, scheme := range schemes {
		status, body, err := httpGet(ctx, clientFor(scheme), scheme+"://"+host+"/.git/config")
		if err == nil && status == 200 && (strings.Contains(body, "[core]") || strings.Contains(body, "[remote")) {
			return &Finding{ID: "git-dir-exposed", Severity: "high",
				Title:  ".git directory exposed over HTTP",
				Detail: scheme + "://" + host + "/.git/config is downloadable — the full source history (and secrets in past commits) can be reconstructed. Block .git at the web server."}
		}
	}
	return nil
}

func probeEnvExposed(ctx context.Context, host string) *Finding {
	return envHTTPAt(ctx, host, []string{"http", "https"})
}
func envHTTPAt(ctx context.Context, host string, schemes []string) *Finding {
	for _, scheme := range schemes {
		status, body, err := httpGet(ctx, clientFor(scheme), scheme+"://"+host+"/.env")
		if err == nil && status == 200 && envPattern.MatchString(body) {
			return &Finding{ID: "env-file-exposed", Severity: "critical",
				Title:  ".env file exposed over HTTP",
				Detail: scheme + "://" + host + "/.env is downloadable and contains KEY=value secrets (DB passwords, API keys). Serve it outside the web root / block dotfiles."}
		}
	}
	return nil
}

func probeWeakTLS(ctx context.Context, host string) *Finding {
	return weakTLSAt(ctx, net.JoinHostPort(host, "443"))
}
func weakTLSAt(ctx context.Context, addr string) *Finding {
	// Allow legacy versions to negotiate, then inspect what the server actually accepted.
	d := tls.Dialer{Config: &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil
	}
	defer conn.Close()
	tc, ok := conn.(*tls.Conn)
	if !ok {
		return nil
	}
	state := tc.ConnectionState()
	ver := versionName(state.Version)
	detail := ""
	severity := ""
	switch {
	case state.Version == tls.VersionTLS10 || state.Version == tls.VersionTLS11:
		severity = "medium"
		detail = "Negotiated " + ver + " — deprecated (BEAST/POODLE-class). Disable TLS 1.0/1.1, require 1.2+."
	case len(state.PeerCertificates) > 0 && time.Now().After(state.PeerCertificates[0].NotAfter):
		severity = "medium"
		detail = "TLS certificate expired on " + state.PeerCertificates[0].NotAfter.Format("2006-01-02") + "."
	}
	if severity == "" {
		return nil
	}
	return &Finding{ID: "weak-tls", Severity: severity,
		Title:  "Weak/expired TLS on :443",
		Detail: detail}
}

// endregion probes

func httpGet(ctx context.Context, c *http.Client, rawurl string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return 0, "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return resp.StatusCode, string(body), nil
}

func clientFor(scheme string) *http.Client {
	if scheme == "https" {
		return expHTTPS
	}
	return expHTTP
}

func versionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "TLS"
	}
}

// region STRUCT_ExposuresChecker [DOMAIN(9): Security; CONCEPT(8]: PeriodicScan; TECH(7]: Checker]
// @purpose The periodic security-exposure probe (system-managed, slow cadence). Runs the curated
//
//	Exposures scan and maps the findings to a check Result so the engine persists it and the
//	existing alert rules can fire (e.g. a new open Redis -> critical -> Telegram).
//
// endregion STRUCT_ExposuresChecker
type ExposuresChecker struct{}

func (ExposuresChecker) Type() string { return "exposures" }

// region FUNC_ExposuresChecker_Run [DOMAIN(9): Security; CONCEPT(7]: Scan; TECH(7]: Checker]
// @purpose Run the exposure scan and derive status: critical if any critical finding, warn if
//
//	only high, ok if clean. Findings are carried in Result.Detail for inspection.
//
// @complexity 4
// endregion FUNC_ExposuresChecker_Run
func (ExposuresChecker) Run(ctx context.Context, target string, _ map[string]any) Result {
	if target == "" {
		return Result{Status: StatusUnknown, Message: "empty target"}
	}
	return ExposuresVerdict(Exposures(ctx, target, 12*time.Second))
}

// region FUNC_ExposuresVerdict [DOMAIN(9): Security; CONCEPT(7): Verdict; TECH(4): pure]
// @purpose Map scan findings to a check Result (status + actionable message + detail). Shared by the
//
//	periodic ExposuresChecker and the on-demand /api/vms/{id}/exposures endpoint so a manual scan
//	persists the verdict (and thus the fleet card) immediately — no waiting on the 6h cadence.
//
// @complexity 3
// endregion FUNC_ExposuresVerdict
func ExposuresVerdict(findings []Finding) Result {
	crit, high := 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "critical":
			crit++
		case "high":
			high++
		}
	}
	status := StatusOK
	switch {
	case crit > 0:
		status = StatusCritical
	case high > 0:
		status = StatusWarn
	}
	msg := "no exposures found"
	if len(findings) > 0 {
		// Actionable message: list the finding titles (sorted by severity), truncated.
		parts := make([]string, 0, len(findings))
		for _, f := range findings {
			parts = append(parts, f.Title)
		}
		msg = strings.Join(parts, "; ")
		if len(msg) > 110 {
			msg = msg[:107] + "..."
		}
	}
	return Result{Status: status, Message: msg, Detail: map[string]any{"findings": findings, "critical": crit, "high": high}}
}
