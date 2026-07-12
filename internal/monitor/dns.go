// Package monitor — DNS checker.
//
// region MODULE_CONTRACT [DOMAIN(7): Monitoring; CONCEPT(7): DNS; TECH(7): net]
// @purpose Resolve a hostname to addresses (A/AAAA) and measure lookup latency. A credential-free
// probe (Plane A): confirms the domain resolves from the VM Pulse host's resolver.
// @invariants
//   - Resolution failure / empty answer -> critical.
//   - Never requires VM credentials.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: dns, checker, resolve, lookup, hostname, address, plane A, no creds
// STRUCTURE: ▶ ┌hostname┐ → ○ net.LookupHost → 〈empty? crit〉 → ⊕ addrs → ⎷ Result
package monitor

import (
	"context"
	"net"
	"strings"
	"time"
)

// region STRUCT_DNSChecker [DOMAIN(7): Monitoring; CONCEPT(6): Plugin; TECH(7): net]
// @purpose DNS resolution checker (no credentials).
// endregion STRUCT_DNSChecker
type DNSChecker struct{}

func (DNSChecker) Type() string { return "dns" }

// region FUNC_DNSChecker_Run [DOMAIN(7): Monitoring; CONCEPT(7): Probe; TECH(7): net]
// @purpose Resolve the target hostname and report status, latency and the resolved addresses.
// @complexity 4
// endregion FUNC_DNSChecker_Run
func (DNSChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	host := strings.TrimSpace(target)
	if host == "" {
		return Result{Status: StatusUnknown, Message: "empty target"}
	}
	// Strip a scheme/host from a URL-ish target so "https://x/y" still resolves "x".
	if i := strings.Index(host, "://"); i >= 0 {
		host = host[i+3:]
	}
	if i := strings.IndexAny(host, "/"); i >= 0 {
		host = host[:i]
	}
	timeout := timeoutOf(params, 5*time.Second)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resolver := &net.Resolver{}
	start := time.Now()
	addrs, err := resolver.LookupHost(ctx, host)
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil || len(addrs) == 0 {
		msg := "no answer"
		if err != nil {
			msg = err.Error()
		}
		return Result{Status: StatusCritical, LatencyMS: latency, Message: msg,
			Detail: map[string]any{"host": host}}
	}
	return Result{Status: StatusOK, LatencyMS: latency, Message: strings.Join(addrs, ", "),
		Detail: map[string]any{"host": host, "addrs": addrs}}
}
