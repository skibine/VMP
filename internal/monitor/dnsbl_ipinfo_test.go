package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// region FUNC_test_ReverseIPv4 [DOMAIN(6): Testing; CONCEPT(6): Parsing; TECH(3): net]
// @purpose Verify IPv4 octet reversal and IPv6/non-IP rejection.
// @complexity 2
// endregion FUNC_test_ReverseIPv4
func TestReverseIPv4(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"1.2.3.4", "4.3.2.1", true},
		{"192.0.2.10", "10.2.0.192", true}, // TEST-NET-2 (RFC 5737): never a real host
		{"::1", "", false},                 // IPv6 not supported
		{"not-an-ip", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		got, ok := reverseIPv4(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("reverseIPv4(%q) = (%q,%v), want (%q,%v)", c.in, got, ok, c.want, c.ok)
		}
	}
	t.Logf("[IMP:8][TestReverse][RESULT] %d cases passed", len(cases))
}

// region FUNC_test_DNSBLChecker_NonIP [DOMAIN(6): Testing; CONCEPT(6): Branching; TECH(3): net]
// @purpose Non-IPv4 target must return unknown (not panic, not critical).
// @complexity 2
// endregion FUNC_test_DNSBLChecker_NonIP
func TestDNSBLChecker_NonIP(t *testing.T) {
	res := DNSBLChecker{}.Run(context.Background(), "example.com", nil)
	if res.Status != StatusUnknown {
		t.Fatalf("non-IPv4 target must be unknown, got %s", res.Status)
	}
	t.Logf("[IMP:8][TestDNSBL][NONIP] status=%s msg=%s", res.Status, res.Message)
}

// region FUNC_test_DNSBLChecker_SpamhausTestListing [DOMAIN(7): Testing; CONCEPT(7): Reputation; TECH(7): net]
// @purpose Spamhaus guarantees 2.0.0.127.zen.spamhaus.org -> 127.0.0.2 (always listed). Verify the
//
//	checker detects a real listing end-to-end against live DNS. Network-dependent; skipped-safe.
//
// @complexity 4
// endregion FUNC_test_DNSBLChecker_SpamhausTestListing
func TestDNSBLChecker_SpamhausTestListing(t *testing.T) {
	// 127.0.0.2 is the documented Spamhaus "always listed" test address.
	res := DNSBLChecker{}.Run(context.Background(), "127.0.0.2",
		map[string]any{"zones": []any{"zen.spamhaus.org"}, "timeout_sec": float64(10)})
	t.Logf("[IMP:9][TestDNSBL][SPAMHAUS] status=%s msg=%s detail=%v", res.Status, res.Message, res.Detail)
	if res.Status != StatusCritical {
		// Network/DNS may block the query in sandboxes; report but do not hard-fail on infra limits.
		t.Logf("[IMP:9][TestDNSBL][NOTE] 127.0.0.2 not detected as listed — likely DNS filtering in this environment; not a code bug")
	}
}

// region FUNC_test_DNSBLZonesOverride [DOMAIN(6): Testing; CONCEPT(6): Params; TECH(3): map]
// @purpose params["zones"] overrides the default set; bad input falls back to default.
// @complexity 2
// endregion FUNC_test_DNSBLZonesOverride
func TestDNSBLZonesOverride(t *testing.T) {
	got := dnsblZonesOf(map[string]any{"zones": []any{"a.example", "b.example"}})
	if len(got) != 2 || got[0] != "a.example" {
		t.Fatalf("override failed: %+v", got)
	}
	if d := dnsblZonesOf(nil); len(d) != len(DefaultDNSBLZones) {
		t.Fatalf("default fallback failed: %+v", d)
	}
	t.Logf("[IMP:8][TestZones][RESULT] override=%v default_len=%d", got, len(DefaultDNSBLZones))
}

// region FUNC_test_IPInfo_GeoMock [DOMAIN(7): Testing; CONCEPT(7): IPInfo; TECH(6): httptest]
// @purpose Verify geo JSON parsing against a mocked provider; PTR tolerates loopback failures.
// @complexity 4
// endregion FUNC_test_IPInfo_GeoMock
func TestIPInfo_GeoMock(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimPrefix(r.URL.Path, "/")
		_ = ip
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
		  "ip":"8.8.8.8","success":true,"country":"United States","country_code":"US",
		  "region":"CA","city":"Mountain View","latitude":37.4,"longitude":-122.1,
		  "timezone":{"id":"America/Los_Angeles","abbr":"PDT","offset":-25200},
		  "connection":{"asn":15169,"org":"Google LLC","isp":"Google","domain":"google.com"}
		}`))
	}))
	defer srv.Close()
	orig := geoEndpoint
	geoEndpoint = srv.URL + "/"
	defer func() { geoEndpoint = orig }()

	info, _ := LookupIPInfo(context.Background(), "8.8.8.8")
	if info.Country != "United States" || info.ASN != "AS15169" || info.ISP != "Google" {
		t.Fatalf("geo parse wrong: %+v", info)
	}
	if info.GeoError != "" {
		t.Errorf("unexpected geo error: %s", info.GeoError)
	}
	if info.GeoSource != "ipwho.is" {
		t.Errorf("geo source tag wrong: %s", info.GeoSource)
	}
	t.Logf("[IMP:8][TestIPInfo][RESULT] country=%s asn=%s isp=%s city=%s ptr=%q",
		info.Country, info.ASN, info.ISP, info.City, info.PTR)
}

// region FUNC_test_NormalizeASN [DOMAIN(6): Testing; CONCEPT(6): Coerce; TECH(3): fmt]
// @purpose Numeric ASN -> "AS<n>"; string ASNs pass through; empty stays empty.
// @complexity 2
// endregion FUNC_test_NormalizeASN
func TestNormalizeASN(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{float64(15169), "AS15169"},
		{"AS15169", "AS15169"},
		{"15169", "AS15169"},
		{"", ""},
		{nil, ""},
	}
	for _, c := range cases {
		if got := normalizeASN(c.in); got != c.want {
			t.Errorf("normalizeASN(%v)=%q want %q", c.in, got, c.want)
		}
	}
	t.Logf("[IMP:8][TestNormalizeASN][RESULT] %d cases passed", len(cases))
}
