// Package monitor — quick-status "battery": a fixed set of credential-less probes run in
// parallel to answer "is this box up, and what is reachable?" on VM select.
//
// region MODULE_CONTRACT [DOMAIN(8): Monitoring; CONCEPT(7): Battery, Reachability; TECH(8): goroutines,net,tcp,http,tls,dns]
// @purpose Give the operator an instant ✓/✗ reachability picture (ssh/dns/web/tls) the moment a
//
//	VM is selected, without SSH credentials (Plane A). The ssh/tcp probe is the headline up/down.
//
// @io (ctx, *Registry, store.VM, timeout) -> []ProbeOutcome
// @invariants
//   - Battery ALWAYS returns one ProbeOutcome per non-skipped spec, in the declared order.
//   - A probe error never aborts siblings (parallel, isolated).
//   - The battery context bounds the whole run; slow probes are cut off at timeout.
//
// @rationale
// Q: Why TCP-reach on the SSH port instead of ICMP ping for the headline?
// A: ICMP is frequently filtered (sandboxes, hardened hosts) and needs privileges; a TCP dial
//
//	to the known SSH port is a reliable, unprivileged liveness signal.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: battery, quick status, reachability, ssh, dns, web, tls, probe, liveness, parallel
// STRUCTURE: ▶ ┌vm┐ → ○ buildSpecs(ip/host/port) → ⚡ ctx-timeout → ∥ ∋spec: chk.Run → ⊕ outcomes[name] → ⎋ ordered []ProbeOutcome
package monitor

import (
	"context"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/skibine/vmp/internal/store"
)

// ProbeSpec is one probe in the battery: a friendly name + checker invocation.
type ProbeSpec struct {
	Name   string         // friendly label shown in UI ("ssh", "dns", "web", "tls")
	Type   string         // checker type ("tcp", "http", "tls", "dns")
	Target string         // probe target
	Params map[string]any // checker params
}

// ProbeOutcome is the result of one battery probe.
type ProbeOutcome struct {
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	LatencyMS float64 `json:"latency_ms"`
	Message   string  `json:"message"`
}

// region FUNC_BuildBatterySpecs [DOMAIN(7): Monitoring; CONCEPT(7): Battery; TECH(5): net]
// @purpose Derive the fixed probe set from VM fields. ssh(tcp on SSH port) is always present;
//
//	dns only when the hostname is a real name (not an IP/empty); web/tls probe the IP|hostname.
//
// @complexity 4
// endregion FUNC_BuildBatterySpecs
func BuildBatterySpecs(vm store.VM) []ProbeSpec {
	host := vm.IP
	if host == "" {
		host = vm.Hostname
	}
	port := strconv.Itoa(vm.PortSSH)
	specs := []ProbeSpec{
		{Name: "ping", Type: "ping", Target: host},
		{Name: "ssh", Type: "tcp", Target: host, Params: map[string]any{"port": port, "timeout_sec": float64(4)}},
	}
	if isDomainName(vm.Hostname) {
		specs = append(specs, ProbeSpec{Name: "dns", Type: "dns", Target: vm.Hostname})
	}
	if host != "" {
		specs = append(specs,
			ProbeSpec{Name: "web", Type: "http", Target: host, Params: map[string]any{"url": httpURL(host), "timeout_sec": float64(4)}},
			ProbeSpec{Name: "tls", Type: "tls", Target: host, Params: map[string]any{"port": "443", "timeout_sec": float64(4)}},
		)
	}
	return specs
}

// httpURL builds an http:// URL for the host, bracketing IPv6 literals (http://[2001:db8::1]/).
func httpURL(host string) string {
	if net.ParseIP(host) != nil && strings.Contains(host, ":") {
		return "http://[" + host + "]/"
	}
	return "http://" + host + "/"
}

// isDomainName reports whether s is a non-empty name that is NOT an IP literal.
func isDomainName(s string) bool {
	if s == "" {
		return false
	}
	if net.ParseIP(s) != nil {
		return false
	}
	return true
}

// region FUNC_Battery [DOMAIN(8): Monitoring; CONCEPT(8): Battery; TECH(8): goroutines,sync]
// @purpose Run all battery probes concurrently under a single deadline and return ordered results.
// @complexity 6
// endregion FUNC_Battery
func Battery(ctx context.Context, reg *Registry, vm store.VM, timeout time.Duration) []ProbeOutcome {
	specs := BuildBatterySpecs(vm)
	bctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out := make([]ProbeOutcome, len(specs))
	var wg sync.WaitGroup
	for i, sp := range specs {
		wg.Add(1)
		go func(i int, sp ProbeSpec) {
			defer wg.Done()
			chk, ok := reg.Get(sp.Type)
			if !ok {
				out[i] = ProbeOutcome{Name: sp.Name, Status: string(StatusUnknown), Message: "no checker: " + sp.Type}
				return
			}
			res := chk.Run(bctx, sp.Target, sp.Params)
			out[i] = ProbeOutcome{Name: sp.Name, Status: string(res.Status), LatencyMS: res.LatencyMS, Message: res.Message}
		}(i, sp)
	}
	wg.Wait()
	return out
}

// Reachable reports whether the box is UP: true if ANY battery probe answered (ping/ssh/web/tls).
// A single port (e.g. ssh:22) being unreachable must NOT flip a reachable box to "down" — only a
// box where nothing responds at all is unreachable.
func Reachable(outcomes []ProbeOutcome) bool {
	for _, o := range outcomes {
		if o.Status == string(StatusOK) {
			return true
		}
	}
	return false
}

// UpVia returns the probe names that proved the box is up (ping/ssh/web/tls), for the UI evidence.
func UpVia(outcomes []ProbeOutcome) []string {
	var via []string
	for _, o := range outcomes {
		if o.Status == string(StatusOK) {
			via = append(via, o.Name)
		}
	}
	return via
}

// SummaryLatency returns the best headline latency: ping first (true RTT), else any ok probe.
func SummaryLatency(outcomes []ProbeOutcome) float64 {
	best := 0.0
	for _, o := range outcomes {
		if o.Status != string(StatusOK) {
			continue
		}
		if o.Name == "ping" {
			return o.LatencyMS
		}
		if best == 0 || (o.LatencyMS > 0 && o.LatencyMS < best) {
			best = o.LatencyMS
		}
	}
	return best
}

// BatterySummary is the JSON shape returned by the /battery endpoint.
type BatterySummary struct {
	Probes    []ProbeOutcome `json:"probes"`
	Reachable bool           `json:"reachable"`
	UpVia     []string       `json:"up_via"`
	LatencyMS float64        `json:"latency_ms"`
}

// Summarize wraps outcomes into a BatterySummary.
func Summarize(outcomes []ProbeOutcome) BatterySummary {
	return BatterySummary{
		Probes:    outcomes,
		Reachable: Reachable(outcomes),
		UpVia:     UpVia(outcomes),
		LatencyMS: SummaryLatency(outcomes),
	}
}
