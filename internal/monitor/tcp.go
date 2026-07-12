// Package monitor — TCP port checker.
//
// region MODULE_CONTRACT [DOMAIN(7): Monitoring; CONCEPT(7): Reachability; TECH(7): net]
// @purpose Verify a TCP port accepts a connection and measure connect latency.
// @invariants
//   - Failure (dial error / timeout) yields StatusCritical, never a panic.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: tcp, checker, port, dial, reachability, latency
// STRUCTURE: ▶ ┌target+port┐ → ○ DialContext → 〈ok? measure〉 → ⊕ Result → ⎷
package monitor

import (
	"context"
	"net"
	"time"
)

// region STRUCT_TCPChecker [DOMAIN(7): Monitoring; CONCEPT(6): Plugin; TECH(7): net]
// @purpose TCP reachability + connect latency checker.
// endregion STRUCT_TCPChecker
type TCPChecker struct{}

func (TCPChecker) Type() string { return "tcp" }

// region FUNC_TCPChecker_Run [DOMAIN(7): Monitoring; CONCEPT(7): Probe; TECH(7): net]
// @purpose Dial target:port within the timeout and report status + latency.
// @complexity 4
// endregion FUNC_TCPChecker_Run
func (TCPChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	port := portOf(params, 80)
	addr := net.JoinHostPort(target, port)
	timeout := timeoutOf(params, 5*time.Second)
	start := time.Now()
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return Result{Status: StatusCritical, LatencyMS: latency, Message: err.Error(),
			Detail: map[string]any{"addr": addr}}
	}
	_ = conn.Close()
	return Result{Status: StatusOK, LatencyMS: latency, Message: "connected",
		Detail: map[string]any{"addr": addr}}
}
