// Package monitor — RDAP fallback for registration-expiry lookup.
//
// region MODULE_CONTRACT [DOMAIN(7): Observability; CONCEPT(7): Whois/RDAP; TECH(8): net/http,json]
// @purpose Resolve a domain's registration expiry via RDAP when classic whois yields nothing. Many
// @purpose modern registries (e.g. Identity Digital's .pro) are RDAP-only: IANA returns an empty
// @purpose `refer:`/`whois:` and the whois server does not answer on port 43. RDAP is queried via
// @purpose the IANA RDAP bootstrap (https://data.iana.org/rdap/dns.json, cached ~24h) -> {base}/domain/{name}.
// @io (ctx, domain) -> (WhoisInfo, error); Expiry is RFC3339-normalized to a bare date.
// @invariants
//   - Unknown/missing expiry => DaysRemaining=-1 (never 0, which would read as "expired").
//   - Never raises; on any error it returns an error so the caller can degrade to unknown.
// @rationale
//   Q: Why a network bootstrap instead of a hardcoded server list?
//   A: The RDAP bootstrap is the authoritative, up-to-date mapping of suffix -> RDAP base URL, so
//      any zone (not just .pro) resolves without per-TLD maintenance.
// endregion MODULE_CONTRACT
// GREP_SUMMARY: rdap, whois fallback, registration expiry, bootstrap, identitydigital, dns.json
// STRUCTURE: ▶ ┌domain┐ → ○ bootstrap(suffix→base, cached) → ⚡ GET {base}/domain/{name} → ⊕ parse events → ⎷ WhoisInfo
package monitor

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// rdapBootstrapURL is the IANA RDAP bootstrap registry (suffix -> RDAP base URL).
var rdapBootstrapURL = "https://data.iana.org/rdap/dns.json"

// rdapFallbackBase is the universal RDAP redirector used when the zone's official base fails
// (dead base in the bootstrap, e.g. .top's rdap.nic.top, or registry port-43 IP blocks). Plain
// HTTPS (443) — the only path that survives registries blocking a client IP. A var so tests can
// point it at a fake server.
var rdapFallbackBase = "https://rdap.org"

// rdapClient carries a HARD timeout: http.DefaultClient has none, and a registry that ACCEPTS the
// TCP connection and then stalls forever (verified: Identity Digital from some home IPs) hung the
// goroutine indefinitely. Background callers (whois checks, domain warmer) run without deadlines,
// so stalled requests piled up until socket exhaustion froze the whole server ("VMPulse завис").
// A var so tests can shrink it.
var rdapClient = &http.Client{Timeout: 8 * time.Second}

var (
	rdapCacheMu   sync.Mutex
	rdapCache     map[string]string
	rdapCachedAt  time.Time
	rdapCacheTTL  = 24 * time.Hour
)

// region FUNC_rdapBaseURL [DOMAIN(7): Observability; CONCEPT(6): Bootstrap; TECH(6): net/http]
// @purpose Map a domain to its RDAP base URL via the IANA bootstrap (cached). Returns "" when the
// @purpose zone has no RDAP service.
// @complexity 5
// endregion FUNC_rdapBaseURL
func rdapBaseURL(ctx context.Context, domain string) (string, error) {
	rdapCacheMu.Lock()
	defer rdapCacheMu.Unlock()
	if rdapCache != nil && time.Since(rdapCachedAt) < rdapCacheTTL {
		base, ok := rdapSuffix(rdapCache, domain)
		if ok {
			return base, nil
		}
		return "", nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdapBootstrapURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var boot struct {
		Services [][]any `json:"services"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&boot); err != nil {
		return "", err
	}
	m := map[string]string{}
	for _, svc := range boot.Services {
		if len(svc) != 2 {
			continue
		}
		suffixes, _ := svc[0].([]any)
		urls, _ := svc[1].([]any)
		if len(urls) == 0 {
			continue
		}
		base, _ := urls[0].(string)
		for _, s := range suffixes {
			if suf, ok := s.(string); ok && base != "" {
				m[strings.ToLower(suf)] = base
			}
		}
	}
	rdapCache, rdapCachedAt = m, time.Now()
	base, ok := rdapSuffix(m, domain)
	if !ok {
		return "", nil
	}
	return base, nil
}

// rdapSuffix finds the longest public suffix in m that matches domain (or is the whole domain).
func rdapSuffix(m map[string]string, domain string) (string, bool) {
	d := strings.ToLower(domain)
	best := ""
	for suf := range m {
		if (d == suf || strings.HasSuffix(d, "."+suf)) && len(suf) > len(best) {
			best = suf
		}
	}
	if best == "" {
		return "", false
	}
	return m[best], true
}

// region FUNC_rdapLookup [DOMAIN(8): Observability; CONCEPT(7): RDAP; TECH(7): net/http,json]
// @purpose Query the zone's RDAP server and extract registration expiry (+ created + registrar).
// @purpose Unknown expiry => DaysRemaining=-1.
// @complexity 7
// endregion FUNC_rdapLookup
func rdapLookup(ctx context.Context, domain string) (WhoisInfo, error) {
	base, err := rdapBaseURL(ctx, domain)
	if err != nil {
		return WhoisInfo{}, err
	}
	if base == "" {
		return WhoisInfo{Status: "error", Error: "zone has no RDAP service"}, nil
	}
	return rdapFetch(ctx, base, domain)
}

// rdapLookupAny races the official bootstrap base and the universal redirector CONCURRENTLY and
// takes the first answer with an expiry. Sequential fallback doubled the worst-case latency (a
// stalling official server ate its whole 8s budget before the redirector even started); in
// parallel the fastest healthy endpoint answers, and a stalled one costs nothing.
func rdapLookupAny(ctx context.Context, domain string) (WhoisInfo, error) {
	type res struct {
		wi  WhoisInfo
		err error
	}
	off := make(chan res, 1)
	fb := make(chan res, 1)
	go func() { wi, err := rdapLookup(ctx, domain); off <- res{wi, err} }()
	go func() { wi, err := rdapFetch(ctx, rdapFallbackBase, domain); fb <- res{wi, err} }()
	firstErr := error(nil)
	for range 2 {
		var r res
		select {
		case r = <-off:
		case r = <-fb:
		}
		if r.err == nil && r.wi.Expiry != "" {
			return r.wi, nil
		}
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
	}
	if firstErr != nil {
		return WhoisInfo{}, firstErr
	}
	return WhoisInfo{Status: "error", Error: "rdap: no expiry from either endpoint"}, nil
}

// rdapFetch queries {base}/domain/{name} and parses the standard RDAP object.
func rdapFetch(ctx context.Context, base, domain string) (WhoisInfo, error) {
	url := strings.TrimSuffix(base, "/") + "/domain/" + domain
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return WhoisInfo{}, err
	}
	req.Header.Set("Accept", "application/rdap+json")
	resp, err := rdapClient.Do(req)
	if err != nil {
		return WhoisInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return WhoisInfo{Status: "error", Error: "rdap http " + resp.Status}, nil
	}
	var obj struct {
		Events   []struct {
			EventAction string `json:"eventAction"`
			EventDate   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles     []string `json:"roles"`
			VCardArray []any   `json:"vcardArray"`
		} `json:"entities"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return WhoisInfo{}, err
	}
	wi := WhoisInfo{Status: "ok", DaysRemaining: -1}
	var created, expiry string
	for _, ev := range obj.Events {
		switch ev.EventAction {
		case "expiration":
			expiry = ev.EventDate
		case "registration":
			created = ev.EventDate
		}
	}
	for _, e := range obj.Entities {
		if containsRole(e.Roles, "registrar") {
			if n := rdapVcardFN(e.VCardArray); n != "" {
				wi.Registrar = n
			}
			break
		}
	}
	wi.Created = created
	if expiry != "" {
		if t, ok := parseExpiryDate(expiry); ok {
			wi.Expiry = t.UTC().Format("2006-01-02")
			wi.DaysRemaining = int(time.Until(t).Hours() / 24)
		} else {
			wi.Expiry = expiry
			wi.DaysRemaining = -1
		}
	}
	return wi, nil
}

func containsRole(roles []string, want string) bool {
	for _, r := range roles {
		if strings.EqualFold(r, want) {
			return true
		}
	}
	return false
}

// rdapVcardFN extracts the "fn" (full name) property from an RDAP vcardArray. The structure is
// ["vcard", [ [ "fn", {}, "text", "Name" ], ... ]].
func rdapVcardFN(v []any) string {
	if len(v) < 2 {
		return ""
	}
	props, ok := v[1].([]any)
	if !ok {
		return ""
	}
	for _, p := range props {
		arr, ok := p.([]any)
		if !ok || len(arr) < 4 {
			continue
		}
		name, _ := arr[0].(string)
		if name == "fn" {
			if val, ok := arr[3].(string); ok {
				return val
			}
		}
	}
	return ""
}
