// Package monitor — TLS certificate checker.
//
// region MODULE_CONTRACT [DOMAIN(7): Monitoring; CONCEPT(8): TLS; TECH(8): crypto/tls]
// @purpose Perform a TLS handshake and inspect the peer certificate's notAfter, reporting
//
//	days until expiry. Critical when already expired, warn when below a threshold.
//
// @invariants
//   - Handshake failure -> critical.
//   - Detail always carries not_after (RFC3339) and days_remaining when a cert is seen.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: tls, checker, certificate, expiry, notAfter, handshake, days remaining
// STRUCTURE: ▶ ┌host:443┐ → ○ tls.DialWithDialer → ⊕ PeerCerts[0] → 〈days? warn/crit〉 → ⎷ Result
package monitor

import (
	"context"
	"crypto/tls"
	"net"
	"time"
)

// region STRUCT_TLSChecker [DOMAIN(7): Monitoring; CONCEPT(6): Plugin; TECH(8): crypto/tls]
// @purpose TLS handshake + certificate expiry checker.
// endregion STRUCT_TLSChecker
type TLSChecker struct{}

func (TLSChecker) Type() string { return "tls" }

// region FUNC_TLSChecker_Run [DOMAIN(7): Monitoring; CONCEPT(7): Probe; TECH(8): crypto/tls]
// @purpose Dial target:port with TLS and evaluate the leaf certificate expiry.
// @complexity 5
// endregion FUNC_TLSChecker_Run
func (TLSChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	port := portOf(params, 443)
	addr := net.JoinHostPort(target, port)
	timeout := timeoutOf(params, 5*time.Second)
	dialer := &net.Dialer{Timeout: timeout}
	cfg := &tls.Config{ServerName: target}
	if boolOf(params, "insecure", false) {
		// For internal self-signed services: skip chain verification but still parse + report
		// the presented certificate's expiry. Plane A is observability, not authn.
		cfg.InsecureSkipVerify = true
	}
	start := time.Now()
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, cfg)
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return Result{Status: StatusCritical, LatencyMS: latency, Message: err.Error(),
			Detail: map[string]any{"addr": addr}}
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return Result{Status: StatusCritical, Message: "no peer certificate",
			Detail: map[string]any{"addr": addr}}
	}
	leaf := certs[0]
	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	detail := map[string]any{
		"addr": addr, "not_after": leaf.NotAfter.UTC().Format(time.RFC3339), "days_remaining": days,
	}
	switch {
	case days < 0:
		return Result{Status: StatusCritical, LatencyMS: latency, Message: "certificate expired", Detail: detail}
	case days < warnDays(params, 14):
		return Result{Status: StatusWarn, LatencyMS: latency, Message: "certificate expiring soon", Detail: detail}
	default:
		return Result{Status: StatusOK, LatencyMS: latency, Message: "valid certificate", Detail: detail}
	}
}

// warnDays reads params["warn_days"] (default def) for the expiry warning window.
func warnDays(params map[string]any, def int) int {
	return intOf(params, "warn_days", def)
}
