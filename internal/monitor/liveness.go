// Package monitor — composite liveness: "is the box up?" via the most reliable available method.
//
// region MODULE_CONTRACT [DOMAIN(8): Monitoring; CONCEPT(8): Liveness; TECH(7): net,parallel]
// @purpose A robust always-on liveness signal that does NOT depend on a single port or on ICMP
//
//	privileges. The box is UP if ANY of: ICMP echo, TCP to the SSH port, :80, :443 responds.
//	This drives the fleet status dot independently of alert configuration.
//
// @io (ctx, target, params{port?}) -> Result{status, latency, detail{via}}
// @invariants
//   - No privileges required: ICMP is tried first but TCP sub-probes need only a normal socket.
//   - A box on a non-standard SSH port still reads UP via :80/:443/ping.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: liveness, up, down, reachability, composite, ping, tcp, system check, dot
// STRUCTURE: ▶ ┌target,port┐ → ∥ ◇ ping + tcp:ssh + tcp:80 + tcp:443 → 〈any ok?〉 → ⎋ ok|critical
package monitor

import (
	"context"
	"net"
	"sync"
	"time"
)

// LivenessChecker is the composite up/down probe used for the always-on system liveness check.
type LivenessChecker struct{}

func (LivenessChecker) Type() string { return "liveness" }

// region FUNC_LivenessChecker_Run [DOMAIN(8): Monitoring; CONCEPT(8]: Liveness; TECH(7]: net]
// @purpose Run all liveness sub-probes concurrently; UP if any answers.
// @complexity 6
// endregion FUNC_LivenessChecker_Run
func (LivenessChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	if target == "" {
		return Result{Status: StatusUnknown, Message: "empty target"}
	}
	timeout := timeoutOf(params, 5*time.Second)
	port := portOf(params, 0) // "" = skip the ssh-port sub-probe
	lctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type sub struct {
		via string
		ok  bool
		lat time.Duration
	}
	subs := []sub{{via: "ping"}, {via: "ssh"}, {via: "web"}, {via: "tls"}}
	var wg sync.WaitGroup
	start := time.Now()
	for i := range subs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := &subs[i]
			t0 := time.Now()
			switch s.via {
			case "ping":
				if r := (PingChecker{}).Run(lctx, target, map[string]any{"timeout_sec": float64(timeout.Seconds())}); r.Status == StatusOK {
					s.ok, s.lat = true, time.Since(t0)
				}
			case "ssh":
				if port != "" {
					if r := (TCPChecker{}).Run(lctx, target, map[string]any{"port": port, "timeout_sec": float64(timeout.Seconds())}); r.Status == StatusOK {
						s.ok, s.lat = true, time.Since(t0)
					}
				}
			case "web":
				if r := (TCPChecker{}).Run(lctx, target, map[string]any{"port": "80", "timeout_sec": float64(timeout.Seconds())}); r.Status == StatusOK {
					s.ok, s.lat = true, time.Since(t0)
				}
			case "tls":
				if r := (TCPChecker{}).Run(lctx, target, map[string]any{"port": "443", "timeout_sec": float64(timeout.Seconds())}); r.Status == StatusOK {
					s.ok, s.lat = true, time.Since(t0)
				}
			}
		}(i)
	}
	wg.Wait()

	via := ""
	var lat time.Duration
	for _, s := range subs {
		if s.ok {
			via = s.via
			lat = s.lat
			break
		}
	}
	if via != "" {
		return Result{Status: StatusOK, LatencyMS: float64(lat.Microseconds()) / 1000.0,
			Message: "up via " + via, Detail: map[string]any{"via": via}}
	}
	_ = start
	return Result{Status: StatusCritical, Message: "no response (ping/ssh/web/tls all failed)",
		Detail: map[string]any{"checked": []string{"ping", "ssh", "web", "tls"}}}
}

// (net import kept for potential future use / JoinHostPort consistency.)
var _ = net.JoinHostPort
