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
	"sync"
	"time"

	"github.com/skibine/vm-pulse/internal/store"
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
		{Name: "ssh", Type: "tcp", Target: host, Params: map[string]any{"port": port, "timeout_sec": float64(4)}},
	}
	if isDomainName(vm.Hostname) {
		specs = append(specs, ProbeSpec{Name: "dns", Type: "dns", Target: vm.Hostname})
	}
	if host != "" {
		specs = append(specs,
			ProbeSpec{Name: "web", Type: "http", Target: host, Params: map[string]any{"url": "http://" + host + "/", "timeout_sec": float64(4)}},
			ProbeSpec{Name: "tls", Type: "tls", Target: host, Params: map[string]any{"port": "443", "timeout_sec": float64(4)}},
		)
	}
	return specs
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

// Reachable reports whether the ssh/tcp probe in the battery succeeded (the box is up).
func Reachable(outcomes []ProbeOutcome) bool {
	for _, o := range outcomes {
		if o.Name == "ssh" {
			return o.Status == string(StatusOK)
		}
	}
	return false
}

// SummaryLatency returns the ssh probe latency (headline), 0 if absent.
func SummaryLatency(outcomes []ProbeOutcome) float64 {
	for _, o := range outcomes {
		if o.Name == "ssh" {
			return o.LatencyMS
		}
	}
	return 0
}

// BatterySummary is the JSON shape returned by the /battery endpoint.
type BatterySummary struct {
	Probes    []ProbeOutcome `json:"probes"`
	Reachable bool           `json:"reachable"`
	LatencyMS float64        `json:"latency_ms"`
}

// Summarize wraps outcomes into a BatterySummary.
func Summarize(outcomes []ProbeOutcome) BatterySummary {
	return BatterySummary{
		Probes:    outcomes,
		Reachable: Reachable(outcomes),
		LatencyMS: SummaryLatency(outcomes),
	}
}
