// Package monitor — WHOIS checker (registration expiry aware).
//
// region MODULE_CONTRACT [DOMAIN(7): Monitoring; CONCEPT(7): Whois; TECH(8): net]
// @purpose Query a domain's WHOIS record (2-hop via IANA referral), parse the registration expiry,
//
//	and report status from days-until-expiry so the alert engine can fire a "domain expiring"
//	rule. Reuses whoisLookup + parseWhoisFields + parseExpiryDate from domaininfo.go.
//
// @invariants
//   - Connection failure / unparseable response -> critical.
//   - Expired (< 0 days) -> critical. Below warn_days (default 30, param "warn_days") -> warn.
//   - Expiry present but unparseable (rare TLD) -> ok with "expiry unknown".
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: whois, checker, domain, registration, expiry, days remaining, port 43
// STRUCTURE: ▶ ┌domain┐ → ○ whoisLookup(2-hop) → parseWhoisFields → parseExpiryDate → 〈days? warn/crit〉 → ⎷ Result
package monitor

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// region STRUCT_WhoisChecker [DOMAIN(7): Monitoring; CONCEPT(6): Plugin; TECH(7): net]
// @purpose WHOIS registration-expiry checker.
// endregion STRUCT_WhoisChecker
type WhoisChecker struct{}

func (WhoisChecker) Type() string { return "whois" }

// region FUNC_WhoisChecker_Run [DOMAIN(7): Monitoring; CONCEPT(7): Probe; TECH(8): net,whois]
// @purpose Query the authoritative WHOIS for the domain and derive status from registration expiry.
// @complexity 6
// endregion FUNC_WhoisChecker_Run
func (WhoisChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	if strings.TrimSpace(target) == "" {
		return Result{Status: StatusUnknown, Message: "empty target"}
	}
	warnDays := intOf(params, "warn_days", 30)
	start := time.Now()
	wi, err := whoisLookup(ctx, target)
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return Result{Status: StatusCritical, LatencyMS: latency, Message: "whois: " + err.Error(),
			Detail: map[string]any{"target": target}}
	}
	detail := map[string]any{
		"target": target, "registrar": wi.Registrar, "expiry": wi.Expiry,
	}
	if wi.Expiry == "" {
		detail["days_remaining"] = -1
		return Result{Status: StatusOK, LatencyMS: latency,
			Message: "whois ok — no expiry field", Detail: detail}
	}
	exp, ok := parseExpiryDate(wi.Expiry)
	if !ok {
		detail["days_remaining"] = -1
		return Result{Status: StatusOK, LatencyMS: latency,
			Message: "whois ok — expiry unparseable: " + wi.Expiry, Detail: detail}
	}
	days := int(time.Until(exp).Hours() / 24)
	detail["days_remaining"] = days
	detail["expiry_date"] = exp.UTC().Format(time.RFC3339)
	switch {
	case days < 0:
		return Result{Status: StatusCritical, LatencyMS: latency,
			Message: fmt.Sprintf("registration expired %d day(s) ago", -days), Detail: detail}
	case days < warnDays:
		return Result{Status: StatusWarn, LatencyMS: latency,
			Message: fmt.Sprintf("registration expires in %d day(s)", days), Detail: detail}
	default:
		return Result{Status: StatusOK, LatencyMS: latency,
			Message: fmt.Sprintf("registration ok (%d days)", days), Detail: detail}
	}
}
