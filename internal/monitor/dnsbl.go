// Package monitor — DNSBL (DNS-based blocklist) IP-reputation checker.
//
// region MODULE_CONTRACT [DOMAIN(8): Monitoring; CONCEPT(7): DNSBL, Reputation; TECH(7): net,DNS]
// @purpose Tell the operator whether a VM's public IP is listed on any spam/blocklist. For a
//
//	mail-sending VM this is critical health: a listing means outbound mail gets rejected/dropped.
//
// @io (ctx, ip, params{zones?}) -> Result{status, detail{listed[], zones_checked, listed_count}}
// @invariants
//   - DNSBL is credential-free and key-free: it is pure DNS against public blocklist zones.
//   - IPv4 only (IPv6 uses a different nibble format and is reported as unknown, not an error).
//   - Any listing -> critical (mail reputation is actionable regardless of which zone).
//
// @rationale
// Q: Why pure DNS instead of an HTTP reputation API?
// A: DNSBL is the industry-standard, keyless protocol: reverse the IP octets, append the zone,
//
//	a returned A record (127.0.0.x) means "listed". No rate limits, no API keys, no signup.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: dnsbl, dnsbl, blocklist, blacklist, spam, reputation, spamhaus, barracuda, spamcop, ip
// STRUCTURE: ▶ ┌ip┐ → ○ reverseIPv4 → ∥ ∋zone: LookupHost(<rev>.zone) → 〈A-record? listed⟩ → ⊕ listed[] → ⎋ ok|critical
package monitor

import (
	"context"
	"fmt"
	"net"
	"time"
)

// DefaultDNSBLZones are reputable, publicly-queryable DNSBL zones. Override via params["zones"].
var DefaultDNSBLZones = []string{
	"zen.spamhaus.org", // SBL + XBL + PBL composite (the canonical signal)
	"b.barracudacentral.org",
	"bl.spamcop.net",
}

// region STRUCT_DNSBLChecker [DOMAIN(7): Monitoring; CONCEPT(6): Plugin; TECH(7): net]
// @purpose DNSBL IP-reputation checker (no credentials, no API key).
// endregion STRUCT_DNSBLChecker
type DNSBLChecker struct{}

func (DNSBLChecker) Type() string { return "dnsbl" }

// region FUNC_DNSBLChecker_Run [DOMAIN(8): Monitoring; CONCEPT(7): Reputation; TECH(7): net]
// @purpose Query each DNSBL zone for the reversed IP; collect any listings and report reputation.
// @complexity 5
// endregion FUNC_DNSBLChecker_Run
func (DNSBLChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	rev, ok := reverseIPv4(target)
	if !ok {
		return Result{Status: StatusUnknown, Message: "dnsbl requires an IPv4 target"}
	}
	zones := dnsblZonesOf(params)
	timeout := timeoutOf(params, 8*time.Second)
	qctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	resolver := net.DefaultResolver

	start := time.Now()
	listed := []map[string]any{}
	for _, z := range zones {
		q := rev + "." + z
		addrs, err := resolver.LookupHost(qctx, q)
		if err == nil && len(addrs) > 0 {
			reason := ""
			if txts, err := resolver.LookupTXT(qctx, q); err == nil && len(txts) > 0 {
				reason = txts[0]
			}
			listed = append(listed, map[string]any{"zone": z, "code": addrs[0], "reason": reason})
		}
	}
	latency := float64(time.Since(start).Microseconds()) / 1000.0

	status := StatusOK
	msg := fmt.Sprintf("clean (%d zones)", len(zones))
	if n := len(listed); n > 0 {
		status = StatusCritical
		msg = fmt.Sprintf("listed on %d/%d DNSBL zones", n, len(zones))
	}
	return Result{Status: status, LatencyMS: latency, Message: msg,
		Detail: map[string]any{
			"ip":            target,
			"listed":        listed,
			"zones_checked": len(zones),
			"listed_count":  len(listed),
		}}
}

// reverseIPv4 turns "1.2.3.4" into "4.3.2.1"; returns false for non-IPv4.
func reverseIPv4(ip string) (string, bool) {
	p := net.ParseIP(ip)
	if p == nil {
		return "", false
	}
	p4 := p.To4()
	if p4 == nil {
		return "", false
	}
	return fmt.Sprintf("%d.%d.%d.%d", p4[3], p4[2], p4[1], p4[0]), true
}

// dnsblZonesOf resolves params["zones"] ([]any of strings) or falls back to the default set.
func dnsblZonesOf(params map[string]any) []string {
	if v, ok := params["zones"]; ok {
		if arr, ok := v.([]any); ok && len(arr) > 0 {
			out := make([]string, 0, len(arr))
			for _, z := range arr {
				if s, ok := z.(string); ok && s != "" {
					out = append(out, s)
				}
			}
			if len(out) > 0 {
				return out
			}
		}
	}
	return DefaultDNSBLZones
}
