package monitor

import (
	"context"
	"testing"
)

// region FUNC_test_ParseWhoisFields [DOMAIN(6): Testing; CONCEPT(6]: Parsing; TECH(4]: regex]
// @purpose Verify registrar/created/expiry extraction across common whois formats.
// @complexity 2
// endregion FUNC_test_ParseWhoisFields
func TestParseWhoisFields(t *testing.T) {
	body := `Domain Name: EXAMPLE.COM
Registrar: Internet Corporation for Assigned Names and Numbers
Creation Date: 1995-08-14T04:00:00Z
Registry Expiry Date: 2026-08-13T04:00:00Z`
	wi := parseWhoisFields(body)
	if wi.Registrar != "Internet Corporation for Assigned Names and Numbers" {
		t.Errorf("registrar wrong: %q", wi.Registrar)
	}
	if wi.Created != "1995-08-14T04:00:00Z" {
		t.Errorf("created wrong: %q", wi.Created)
	}
	// Expiry is normalized to a bare date (no time) and days_remaining computed, like the cert block.
	if wi.Expiry != "2026-08-13" {
		t.Errorf("expiry want normalized date 2026-08-13, got %q", wi.Expiry)
	}
	if wi.DaysRemaining == -1 {
		t.Errorf("days_remaining want parsed value, got -1")
	}
	if wi.Status != "ok" {
		t.Errorf("status want ok, got %s", wi.Status)
	}
	t.Logf("[IMP:8][TestWhois][RESULT] registrar=%q created=%q expiry=%q days=%d", wi.Registrar, wi.Created, wi.Expiry, wi.DaysRemaining)
}

// region FUNC_test_ParseWhoisFields_Unparseable [DOMAIN(6): Testing; CONCEPT(6): Parsing; TECH(4): regex]
// @purpose A registrar expiry in an unknown format must NOT be treated as expired: days_remaining = -1,
// @purpose the raw string is kept, and status stays "ok".
// @complexity 2
// endregion FUNC_test_ParseWhoisFields_Unparseable
func TestParseWhoisFields_Unparseable(t *testing.T) {
	body := `Domain Name: WEIRD.TLD
Registrar: Some Registrar
Registry Expiry Date: 17-Mardu-2099 12:99:99 UTC`
	wi := parseWhoisFields(body)
	if wi.Expiry != "17-Mardu-2099 12:99:99 UTC" {
		t.Errorf("unparseable expiry should stay raw, got %q", wi.Expiry)
	}
	if wi.DaysRemaining != -1 {
		t.Errorf("unparseable days_remaining want -1, got %d", wi.DaysRemaining)
	}
	if wi.Status != "ok" {
		t.Errorf("unparseable expiry should keep status ok, got %s", wi.Status)
	}
	t.Logf("[IMP:8][TestWhoisUnparseable][RESULT] expiry=%q days=%d status=%s", wi.Expiry, wi.DaysRemaining, wi.Status)
}

// region FUNC_test_ParseWhoisFields_NoExpiry [DOMAIN(7): Testing; CONCEPT(8): Unknown; TECH(4): regex]
// @purpose A whois body without an expiry field must read as "unknown" (days=-1), NOT as "0 days"
// @purpose (= expired). This is the guard against flagging RDAP-only zones (e.g. .pro) as expired.
// @complexity 2
// endregion FUNC_test_ParseWhoisFields_NoExpiry
func TestParseWhoisFields_NoExpiry(t *testing.T) {
	body := `Domain Name: NOPRO.TLD
Registrar: Some Registrar
Creation Date: 2020-01-01T00:00:00Z`
	wi := parseWhoisFields(body)
	if wi.Expiry != "" {
		t.Errorf("expected no expiry, got %q", wi.Expiry)
	}
	if wi.DaysRemaining != -1 {
		t.Errorf("unknown expiry must be days=-1, got %d", wi.DaysRemaining)
	}
	t.Logf("[IMP:8][TestWhoisNoExpiry][RESULT] expiry=%q days=%d", wi.Expiry, wi.DaysRemaining)
}

// region FUNC_test_DNSSignature_OrderStable [DOMAIN(7): Testing; CONCEPT(7): DNSChange; TECH(5): sha256]
// @purpose The DNS signature must be stable under record reordering (servers return NS/MX/A in
// @purpose arbitrary order) and change only when the actual set changes. This underpins the
// @purpose fleet "dns records changed" status — an order-sensitive hash would false-alarm.
// @complexity 3
// endregion FUNC_test_DNSSignature_OrderStable
func TestDNSSignature_OrderStable(t *testing.T) {
	base := DNSRecords{
		A:    []string{"1.1.1.1", "2.2.2.2"},
		NS:   []string{"ns1.ex.com", "ns2.ex.com", "ns3.ex.com"},
		MX:   []string{"10 mail.ex.com"},
		TXT:  []string{"v=spf1 -all"},
		AAAA: []string{"::1"},
	}
	// Same records, different order within each set — must hash identically.
	reordered := DNSRecords{
		A:    []string{"2.2.2.2", "1.1.1.1"},
		NS:   []string{"ns3.ex.com", "ns1.ex.com", "ns2.ex.com"},
		MX:   []string{"10 mail.ex.com"},
		TXT:  []string{"v=spf1 -all"},
		AAAA: []string{"::1"},
	}
	if DNSSignature(base) != DNSSignature(reordered) {
		t.Errorf("signature not order-stable: %q vs %q", DNSSignature(base), DNSSignature(reordered))
	}
	// A/AAAA rotation (CDN) must NOT alter the signature — that was the false-positive source.
	cdRotated := base
	cdRotated.A = []string{"1.1.1.1", "9.9.9.9"}
	cdRotated.AAAA = []string{"::2", "::3"}
	if DNSSignature(base) != DNSSignature(cdRotated) {
		t.Errorf("signature should NOT change when only A/AAAA rotate (CDN noise)")
	}
	// A change to a control record (NS/MX/TXT — the takeover signals) must alter the signature.
	changed := base
	changed.NS = []string{"ns1.evil.com", "ns2.evil.com"}
	if DNSSignature(base) == DNSSignature(changed) {
		t.Errorf("signature should change when a control record (NS/MX/TXT) changes")
	}
	t.Logf("[IMP:8][TestDNSSig][RESULT] stable=%t immuneToCDN=%t sensitiveToControlChange=%t", DNSSignature(base) == DNSSignature(reordered), DNSSignature(base) == DNSSignature(cdRotated), DNSSignature(base) != DNSSignature(changed))
}

// region FUNC_test_ParseRefer [DOMAIN(6): Testing; CONCEPT(6]: Parsing; TECH(3]: regex]
// @purpose Verify IANA referral server extraction.
// @complexity 2
// endregion FUNC_test_ParseRefer
func TestParseRefer(t *testing.T) {
	body := `domain:       COM
refer:        whois.verisign-grs.com
`
	if got := parseRefer(body); got != "whois.verisign-grs.com" {
		t.Fatalf("refer wrong: %q", got)
	}
	if got := parseRefer("no refer here"); got != "" {
		t.Fatalf("expected empty refer, got %q", got)
	}
	t.Logf("[IMP:8][TestRefer][RESULT] refer=whois.verisign-grs.com")
}

// region FUNC_test_DomainInfo_Live [DOMAIN(7): Testing; CONCEPT(7]: DomainInfo; TECH(7]: net]
// @purpose Live end-to-end against example.com (DNS + cert + whois). Network-dependent.
// @complexity 4
// endregion FUNC_DomainInfo_Live
func TestDomainInfo_Live(t *testing.T) {
	info, err := ProbeDomain(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("DomainInfo: %v", err)
	}
	if len(info.DNS.A) == 0 {
		t.Logf("[IMP:8][TestDomainInfo][NOTE] no A records (network/DNS filtering?)")
	}
	if info.Cert.Present {
		t.Logf("[IMP:8][TestDomainInfo][CERT] issuer=%s days=%d status=%s", info.Cert.Issuer, info.Cert.DaysRemaining, info.Cert.Status)
	} else {
		t.Logf("[IMP:8][TestDomainInfo][NOTE] no cert (port 443 blocked?)")
	}
	if info.Whois.Created != "" {
		t.Logf("[IMP:8][TestDomainInfo][WHOIS] registrar=%s created=%s", info.Whois.Registrar, info.Whois.Created)
	}
	// Structural invariants regardless of network.
	if info.Domain != "example.com" {
		t.Errorf("domain wrong: %q", info.Domain)
	}
}
