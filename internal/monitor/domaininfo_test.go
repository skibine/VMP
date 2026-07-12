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
	if wi.Expiry != "2026-08-13T04:00:00Z" {
		t.Errorf("expiry wrong: %q", wi.Expiry)
	}
	if wi.Status != "ok" {
		t.Errorf("status want ok, got %s", wi.Status)
	}
	t.Logf("[IMP:8][TestWhois][RESULT] registrar=%q created=%q expiry=%q", wi.Registrar, wi.Created, wi.Expiry)
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
