// Package monitor — domain information: DNS records + TLS certificate + whois (registrar/age/expiry).
//
// region MODULE_CONTRACT [DOMAIN(8): Observability; CONCEPT(7): DomainInfo; TECH(8): net,tls,whois]
// @purpose Answer "what do I know about this domain?" in one shot: its DNS records, the TLS cert
//
//	issuer + days until expiry, and the registrar + creation/expiry dates from whois. All
//	credential-free (Plane A): pure external DNS, TLS and whois lookups from the VM Pulse host.
//
// @io (ctx, domain) -> (DomainInfo, error)
// @invariants
//   - Each sub-probe is independent: a whois/TLS failure degrades to a partial result, never aborts.
//   - whois follows the IANA referral (2-hop) so registrar/created/expiry come from the authoritative
//     server, not the IANA root.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: domaininfo, domain, dns records, mx, ns, txt, tls cert, expiry, whois, registrar, creation date
// STRUCTURE: ▶ ┌domain┐ → ∥ ◇ DNS(A/AAAA/MX/NS/TXT) + ◇ cert(domain:443) + ◇ whois(2-hop) → ⊕ merge → ⎷ DomainInfo
package monitor

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"
)

// DomainInfo is the aggregated domain picture.
type DomainInfo struct {
	Domain string     `json:"domain"`
	DNS    DNSRecords `json:"dns"`
	Cert   CertInfo   `json:"cert"`
	Whois  WhoisInfo  `json:"whois"`
}

// DNSRecords holds the resolved record sets.
type DNSRecords struct {
	A    []string `json:"a"`
	AAAA []string `json:"aaaa"`
	MX   []string `json:"mx"` // "pref host"
	NS   []string `json:"ns"`
	TXT  []string `json:"txt"`
}

// CertInfo is the TLS leaf-certificate summary.
type CertInfo struct {
	Present       bool   `json:"present"`
	Issuer        string `json:"issuer"`
	Subject       string `json:"subject"`
	NotAfter      string `json:"not_after"`
	DaysRemaining int    `json:"days_remaining"`
	Status        string `json:"status"` // ok | expiring | expired | none
}

// WhoisInfo is the parsed registrar record.
type WhoisInfo struct {
	Registrar string `json:"registrar"`
	Created   string `json:"created"`
	Expiry    string `json:"expiry"`
	Status    string `json:"status"` // ok | error
	Error     string `json:"error,omitempty"`
}

// region FUNC_ProbeDomain [DOMAIN(8): Observability; CONCEPT(7): DomainInfo; TECH(8): net,tls,whois]
// @purpose Run DNS + TLS + whois concurrently for a domain and merge into one DomainInfo.
// @complexity 7
// endregion FUNC_ProbeDomain
func ProbeDomain(ctx context.Context, domain string) (DomainInfo, error) {
	domain = strings.TrimPrefix(strings.TrimSpace(domain), "www.")
	info := DomainInfo{Domain: domain}
	deadline, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	// Three independent sub-probes; run concurrently (disjoint fields, safe).
	type dnsRes struct {
		v DNSRecords
		e error
	}
	type certRes struct {
		v CertInfo
		e error
	}
	type whoisRes struct {
		v WhoisInfo
		e error
	}
	dc := make(chan dnsRes, 1)
	cc := make(chan certRes, 1)
	wc := make(chan whoisRes, 1)
	go func() { r, e := lookupDNS(deadline, domain); dc <- dnsRes{r, e} }()
	go func() { r, e := certInfo(deadline, domain); cc <- certRes{r, e} }()
	go func() { r, e := whoisLookup(deadline, domain); wc <- whoisRes{r, e} }()
	if r := <-dc; r.e == nil {
		info.DNS = r.v
	}
	if r := <-cc; r.e == nil {
		info.Cert = r.v
	}
	if r := <-wc; r.e == nil {
		info.Whois = r.v
	}
	return info, nil
}

// region FUNC_lookupDNS [DOMAIN(7): Observability; CONCEPT(7): DNS; TECH(6): net]
// @purpose Resolve A/AAAA/MX/NS/TXT for the domain (each tolerant of NXDOMAIN).
// @complexity 4
// endregion FUNC_lookupDNS
func lookupDNS(ctx context.Context, domain string) (DNSRecords, error) {
	r := net.DefaultResolver
	d := DNSRecords{}
	if ips, err := r.LookupIP(ctx, "ip4", domain); err == nil {
		for _, ip := range ips {
			d.A = append(d.A, ip.String())
		}
	}
	if ips, err := r.LookupIP(ctx, "ip6", domain); err == nil {
		for _, ip := range ips {
			d.AAAA = append(d.AAAA, ip.String())
		}
	}
	if mx, err := r.LookupMX(ctx, domain); err == nil {
		for _, m := range mx {
			d.MX = append(d.MX, fmt.Sprintf("%d %s", m.Pref, strings.TrimSuffix(m.Host, ".")))
		}
	}
	if ns, err := r.LookupNS(ctx, domain); err == nil {
		for _, n := range ns {
			d.NS = append(d.NS, strings.TrimSuffix(n.Host, "."))
		}
	}
	if txt, err := r.LookupTXT(ctx, domain); err == nil {
		d.TXT = txt
	}
	return d, nil
}

// region FUNC_certInfo [DOMAIN(7): Observability; CONCEPT(7): TLS; TECH(7): crypto/tls]
// @purpose Dial domain:443 with TLS and summarize the leaf certificate expiry.
// @complexity 4
// endregion FUNC_certInfo
func certInfo(ctx context.Context, domain string) (CertInfo, error) {
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(domain, "443"),
		&tls.Config{ServerName: domain})
	if err != nil {
		return CertInfo{Status: "none"}, nil
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return CertInfo{Status: "none"}, nil
	}
	leaf := certs[0]
	days := int(time.Until(leaf.NotAfter).Hours() / 24)
	status := "ok"
	switch {
	case days < 0:
		status = "expired"
	case days < 30:
		status = "expiring"
	}
	return CertInfo{
		Present:       true,
		Issuer:        leaf.Issuer.CommonName,
		Subject:       leaf.Subject.CommonName,
		NotAfter:      leaf.NotAfter.UTC().Format(time.RFC3339),
		DaysRemaining: days,
		Status:        status,
	}, nil
}

// region FUNC_whoisLookup [DOMAIN(7): Observability; CONCEPT(7): Whois; TECH(7): net]
// @purpose 2-hop whois: query IANA, follow the referral, parse registrar/created/expiry.
// @complexity 6
// endregion FUNC_whoisLookup
func whoisLookup(ctx context.Context, domain string) (WhoisInfo, error) {
	ref, err := whoisQuery(ctx, domain, "whois.iana.org:43")
	if err != nil {
		return WhoisInfo{Status: "error", Error: err.Error()}, nil
	}
	server := parseRefer(ref)
	body := ref
	if server != "" {
		if b, err := whoisQuery(ctx, domain, server+":43"); err == nil {
			body = b
		}
	}
	return parseWhoisFields(body), nil
}

// whoisQuery opens a TCP whois connection, sends the query, returns the raw text (bounded).
func whoisQuery(ctx context.Context, query, addr string) (string, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	if _, err := conn.Write([]byte(query + "\r\n")); err != nil {
		return "", err
	}
	var sb strings.Builder
	sc := bufio.NewScanner(conn)
	for sc.Scan() {
		sb.WriteString(sc.Text() + "\n")
		if sb.Len() > 64*1024 {
			break
		}
	}
	return sb.String(), nil
}

var reRefer = regexp.MustCompile(`(?im)^\s*refer:\s*(\S+)`)

// parseRefer extracts the authoritative whois server from an IANA referral response.
func parseRefer(body string) string {
	if m := reRefer.FindStringSubmatch(body); len(m) == 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

var (
	reRegistrar = regexp.MustCompile(`(?im)^\s*(registrar(?:\s+name)?|registrar organization):\s*(.+)$`)
	reCreated   = regexp.MustCompile(`(?im)^\s*(creation date|created(?:\s+on)?|registered|registration time):\s*(.+)$`)
	reExpiry    = regexp.MustCompile(`(?im)^\s*(registry expiry date|expiry date|expiration date|paid-till|registrar registration expiration date):\s*(.+)$`)
)

// parseWhoisFields extracts registrar/created/expiry from a whois body (tolerant across TLDs).
func parseWhoisFields(body string) WhoisInfo {
	wi := WhoisInfo{Status: "ok"}
	if m := reRegistrar.FindStringSubmatch(body); len(m) == 3 {
		wi.Registrar = strings.TrimSpace(m[2])
	}
	if m := reCreated.FindStringSubmatch(body); len(m) == 3 {
		wi.Created = strings.TrimSpace(m[2])
	}
	if m := reExpiry.FindStringSubmatch(body); len(m) == 3 {
		wi.Expiry = strings.TrimSpace(m[2])
	}
	if wi.Registrar == "" && wi.Created == "" && wi.Expiry == "" {
		wi.Status = "error"
		wi.Error = "no parseable registrar/created/expiry fields"
	}
	return wi
}
