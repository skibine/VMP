// Package monitor — IP information lookup (GeoIP + ASN + reverse-DNS).
//
// region MODULE_CONTRACT [DOMAIN(8): Monitoring; CONCEPT(7): IPInfo, GeoIP; TECH(7): net/http,net]
// @purpose Tell the operator where a VM's public IP is located, which ASN/ISP hosts it, and its
//
//	reverse-DNS (PTR). Helps identify mis-tagged VMs, verify the hosting region/provider, and spot
//	unexpected PTR changes.
//
// @io (ctx, ip) -> (IPInfo, error)
// @invariants
//   - IPInfo is credential-free (Plane A). Geo/ASN via the keyless ipwho.is HTTPS endpoint.
//   - PTR is always resolved locally (net.LookupAddr) even if the geo endpoint fails.
//   - A failed geo lookup never returns a hard error; it yields partial data + the cause.
//
// @rationale
// Q: Why ipwho.is instead of MaxMind GeoLite2 or ip-api.com?
// A: ipwho.is is free, keyless AND HTTPS (ip-api.com free tier is HTTP-only; GeoLite2 needs a
//
//	license key + a bundled .mmdb download). For a self-hosted fleet tool doing on-demand lookups,
//	keyless HTTPS is the pragmatic, zero-ops choice.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: ipinfo, geoip, asn, ptr, reverse dns, location, isp, ipwho, geo, region, country
// STRUCTURE: ▶ ┌ip┐ → ∥ ◇ geo(ipwho.is JSON) + PTR(net.LookupAddr) → ⊕ merge → ⎷ IPInfo
package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// IPInfo is the merged geo + ASN + PTR picture for a public IP.
type IPInfo struct {
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	Region      string `json:"region"`
	City        string `json:"city"`
	Timezone    string `json:"timezone"`
	Latitude    any    `json:"lat"`
	Longitude   any    `json:"lon"`
	ISP         string `json:"isp"`
	Org         string `json:"org"`
	ASN         string `json:"asn"`
	Domain      string `json:"domain"`
	PTR         string `json:"ptr"`
	GeoSource   string `json:"geo_source,omitempty"`
	GeoError    string `json:"geo_error,omitempty"`
}

// geoEndpoint is the keyless HTTPS provider; overridable in tests via httptest.
var geoEndpoint = "https://ipwho.is/"

// region FUNC_LookupIPInfo [DOMAIN(8): Monitoring; CONCEPT(7): IPInfo; TECH(7): net/http,net]
// @purpose Fetch geo/ASN for the IP and resolve its reverse-DNS; merge into one IPInfo.
// @complexity 5
// endregion FUNC_LookupIPInfo
func LookupIPInfo(ctx context.Context, ip string) (IPInfo, error) {
	info := IPInfo{IP: ip}

	// PTR is resolved locally and independently; never gated by the geo endpoint.
	ptrCtx, ptrCancel := context.WithTimeout(ctx, 4*time.Second)
	if names, err := net.DefaultResolver.LookupAddr(ptrCtx, ip); err == nil && len(names) > 0 {
		info.PTR = strings.TrimSuffix(names[0], ".")
	}
	ptrCancel()

	if err := fetchGeo(ctx, ip, &info); err != nil {
		info.GeoError = err.Error()
	}
	return info, nil
}

// fetchGeo calls the keyless HTTPS provider and decodes geo+ASN into info.
func fetchGeo(ctx context.Context, ip string, info *IPInfo) error {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(hctx, http.MethodGet, geoEndpoint+ip, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("geo http %d", resp.StatusCode)
	}
	var body struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
		Country string `json:"country"`
		Code    string `json:"country_code"`
		Region  string `json:"region"`
		City    string `json:"city"`
		Lat     any    `json:"latitude"`
		Lon     any    `json:"longitude"`
		Conn    struct {
			ASN    any `json:"asn"` // ipwho.is returns a number; some mirrors return a string
			Org    any `json:"org"`
			ISP    any `json:"isp"`
			Domain any `json:"domain"`
		} `json:"connection"`
		TZ struct {
			ID string `json:"id"` // ipwho.is returns timezone as {id, abbr, offset, ...}
		} `json:"timezone"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return err
	}
	if !body.Success {
		return fmt.Errorf("geo provider: %s", body.Message)
	}
	info.GeoSource = "ipwho.is"
	info.Country = body.Country
	info.CountryCode = body.Code
	info.Region = body.Region
	info.City = body.City
	info.Timezone = body.TZ.ID
	info.Latitude = body.Lat
	info.Longitude = body.Lon
	info.ISP = anyStr(body.Conn.ISP)
	info.Org = anyStr(body.Conn.Org)
	info.ASN = normalizeASN(body.Conn.ASN)
	info.Domain = anyStr(body.Conn.Domain)
	return nil
}

// anyStr coerces a JSON-decoded value (string/number) into a trimmed string.
func anyStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprintf("%v", x)
	case bool:
		return fmt.Sprintf("%v", x)
	case nil:
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// normalizeASN turns a numeric ASN (15169) into "AS15169"; string ASNs pass through unchanged.
func normalizeASN(v any) string {
	switch x := v.(type) {
	case string:
		if x == "" {
			return ""
		}
		if !strings.HasPrefix(strings.ToUpper(x), "AS") && isAllDigits(x) {
			return "AS" + x
		}
		return x
	case float64:
		if x == 0 {
			return ""
		}
		return fmt.Sprintf("AS%d", int64(x))
	}
	return anyStr(v)
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}
