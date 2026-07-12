// Package monitor — WHOIS checker.
//
// region MODULE_CONTRACT [DOMAIN(7): Monitoring; CONCEPT(7): Whois; TECH(7): net]
// @purpose Query a WHOIS server for a domain and confirm a non-empty response. Full per-TLD
//
//	expiry parsing is intentionally deferred (registrars vary wildly); this records a
//	response snippet + length so later slices can surface/parse it.
//
// @invariants
//   - Connection failure / empty response -> critical.
//   - A response containing an expiry-like keyword raises detail.has_expiry = true.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: whois, checker, domain, port 43, registrar, response, expiry
// STRUCTURE: ▶ ┌domain┐ → ○ Dial whois:43 → ⚡ send query → ⊕ read → 〈empty? crit〉 → ⎷ Result
package monitor

import (
	"bufio"
	"context"
	"net"
	"strings"
	"time"
)

// region STRUCT_WhoisChecker [DOMAIN(7): Monitoring; CONCEPT(6): Plugin; TECH(7): net]
// @purpose WHOIS query checker.
// endregion STRUCT_WhoisChecker
type WhoisChecker struct{}

func (WhoisChecker) Type() string { return "whois" }

// region FUNC_WhoisChecker_Run [DOMAIN(7): Monitoring; CONCEPT(7): Probe; TECH(7): net]
// @purpose Query the configured WHOIS server (default whois.iana.org) for the target domain.
// @complexity 5
// endregion FUNC_WhoisChecker_Run
func (WhoisChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	if strings.TrimSpace(target) == "" {
		return Result{Status: StatusUnknown, Message: "empty target"}
	}
	server := strOf(params, "server", "whois.iana.org")
	port := strOf(params, "port", "43")
	if port == "" {
		port = "43"
	}
	addr := net.JoinHostPort(server, port)
	timeout := timeoutOf(params, 8*time.Second)
	d := net.Dialer{Timeout: timeout}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", addr)
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return Result{Status: StatusCritical, LatencyMS: latency, Message: err.Error(),
			Detail: map[string]any{"addr": addr}}
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write([]byte(target + "\r\n")); err != nil {
		return Result{Status: StatusCritical, LatencyMS: latency, Message: "write: " + err.Error(),
			Detail: map[string]any{"addr": addr}}
	}
	var sb strings.Builder
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		sb.WriteString(sc.Text() + "\n")
		if sb.Len() > 64*1024 {
			break
		}
	}
	body := sb.String()
	if strings.TrimSpace(body) == "" {
		return Result{Status: StatusCritical, LatencyMS: latency, Message: "empty response",
			Detail: map[string]any{"addr": addr}}
	}
	detail := map[string]any{
		"addr": addr, "bytes": len(body), "has_expiry": containsExpiry(body),
	}
	return Result{Status: StatusOK, LatencyMS: latency, Message: "whois response",
		Detail: detail}
}

// containsExpiry reports whether the body mentions an expiry-like field (best-effort).
func containsExpiry(body string) bool {
	low := strings.ToLower(body)
	for _, kw := range []string{"expiry", "expir", "paid-till", "registry expiry"} {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}
