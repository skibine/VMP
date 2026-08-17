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
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"regexp"
	"slices"
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
	Registrar    string `json:"registrar"`
	Created      string `json:"created"`
	Expiry       string `json:"expiry"`
	DaysRemaining int   `json:"days_remaining"` // -1 when expiry unparseable
	Status       string `json:"status"` // ok | error
	Error        string `json:"error,omitempty"`
	Note         string `json:"note,omitempty"` // e.g. "parent zone: example.top" for 3LD lookups
}

// expiryDateLayouts are the common registrar date formats (tried in order). Whois responses vary
// wildly across TLDs; this covers the dominant ones (.com/.net Verisign, .ru/.de numeric, ISO, etc.).
var expiryDateLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05Z",
	"2006-01-02 15:04:05",
	"2006-01-02",
	"02-Jan-2006",
	"02-Jan-2006 15:04:05",
	"02.01.2006",
	"02.01.2006 15:04:05",
	"2006/01/02",
	"January 2 2006",
	"2 January 2006",
	"02-Jan-06",
}

// parseExpiryDate parses a registrar expiry string into a time.Time (best-effort). ok=false when no
// layout matches (rare TLDs) — callers treat that as "no expiry known" rather than expired.
func parseExpiryDate(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range expiryDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
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

// region FUNC_whoisLookup [DOMAIN(7): Observability; CONCEPT(7): Whois; TECH(7): net,rdap]
// @purpose Resolve a domain's registrar/created/expiry. First the classic 2-hop whois (IANA referral
// @purpose -> authoritative server); if that yields no expiry (many zones are RDAP-only now, e.g.
// @purpose Identity Digital's .pro with an empty IANA `refer:`), fall back to RDAP. Absent expiry is
// @purpose reported as DaysRemaining=-1 (unknown), never as 0.
// @complexity 7
// endregion FUNC_whoisLookup
// region FUNC_whoisLookup [DOMAIN(8): Observability; CONCEPT(7): Registration; TECH(7): net+rdap]
// RESTORED-ORIGINAL: the battle-tested 2-hop lookup (IANA referral -> authoritative registry,
// RDAP fallback when classic whois yields no expiry). The resilience layers added on 2026-08-17
// (static referral table, negative IANA cache, rdap.org redirector, per-leg 25s budget) made the
// chain SLOWER and flakier on some networks (a single slow official RDAP hop could eat the whole
// budget) and were rolled back wholesale at the operator's request. Only two safe bits kept:
// the RDAP-rescue status clear (data present => not an error) and the inert WhoisInfo.Note.
// ianaAddr is the IANA referral endpoint (var so tests inject a fake).
var ianaAddr = "whois.iana.org:43"

// whoisBudget caps the ENTIRE whois chain regardless of the caller's context. Background callers
// (engine whois checks, domain warmer) pass contexts without deadlines; without this cap one
// stalled chain could outlive everything (see rdapClient comment). A var so tests can shrink it.
var whoisBudget = 20 * time.Second

func whoisLookup(ctx context.Context, domain string) (WhoisInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, whoisBudget)
	defer cancel()
	ref, err := whoisQuery(ctx, domain, ianaAddr)
	if err != nil {
		return WhoisInfo{Status: "error", Error: err.Error()}, nil
	}
	// BUG_FIX_CONTEXT (home-IP case, 2026-08-17): some registries (verified: whois.nic.top)
	// ACCEPT the TCP connection and immediately RST it for blocked IP ranges — in Go that reads
	// as an EMPTY response with nil error. Feeding the IANA referral body instead leaked TLD-level
	// data as domain data; feeding "" yields the honest "no parseable fields" that then triggers
	// the RDAP rescue below. Only a non-empty registry answer is trusted.
	server := parseRefer(ref)
	body := ""
	if server != "" {
		if b, qerr := whoisQuery(ctx, domain, server+":43"); qerr == nil && strings.TrimSpace(b) != "" {
			body = b
		}
	}
	wi := parseWhoisFields(body)
	// Classic whois gave no expiry (RDAP-only zone, registry blocked the IP, empty referral,
	// etc.): try RDAP to get the real registration expiry. The official bootstrap base may be
	// dead (verified: .top announces rdap.nic.top which does not resolve) — the universal
	// HTTPS redirector (rdap.org) is the second, port-443-only attempt that survives registry
	// port-43 IP blocks.
	if wi.Expiry == "" {
		if rw, rerr := rdapLookupAny(ctx, domain); rerr == nil && rw.Expiry != "" {
			if wi.Registrar == "" {
				wi.Registrar = rw.Registrar
			}
			if wi.Created == "" {
				wi.Created = rw.Created
			}
			wi.Expiry = rw.Expiry
			wi.DaysRemaining = rw.DaysRemaining
			// RDAP rescued the lookup: the record IS complete — do not show an error next to data.
			wi.Status = "ok"
			wi.Error = ""
		}
	}
	return wi, nil
}

// whoisQuery opens a TCP whois connection, sends the query, returns the raw text (bounded).
// The connection deadline is min(8s, ctx deadline): a stalling server must never outlive the
// caller's budget (whoisLookup caps the whole chain).
func whoisQuery(ctx context.Context, query, addr string) (string, error) {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	dl := time.Now().Add(8 * time.Second)
	if cd, ok := ctx.Deadline(); ok && cd.Before(dl) {
		dl = cd
	}
	_ = conn.SetDeadline(dl)
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

// region FUNC_DNSSignature [DOMAIN(8): Observability; CONCEPT(7): DNSChange; TECH(6): crypto/sha256]
// @purpose Produce a short stable hash of a domain's DNS record set so callers (the reminder
// @purpose evaluator and the domain-health endpoint) can detect changes. Order within each set is
// @purpose normalized before hashing, so reordering a record is not treated as a change.
// @purpose Only the control/delegation records (NS/MX/TXT) are hashed: A/AAAA are excluded because
// @purpose CDN front-ends rotate them constantly, which caused false "DNS changed" yellows. A real
// @purpose takeover changes NS (nameservers) or MX/TXT (mail/verification), so hijacks are still caught.
// @complexity 3
// endregion FUNC_DNSSignature
func DNSSignature(d DNSRecords) string {
	// Sort each set so the hash is order-stable: DNS servers return records in arbitrary order between
	// lookups, and reordering a record must NOT look like a change. A/AAAA are intentionally omitted
	// (CDN rotation noise); NS/MX/TXT are the security-relevant delegation/control records.
	sort := func(s []string) []string { out := append([]string(nil), s...); slices.Sort(out); return out }
	h := sha256.New()
	fmt.Fprintln(h, strings.Join(sort(d.MX), ","))
	fmt.Fprintln(h, strings.Join(sort(d.NS), ","))
	fmt.Fprintln(h, strings.Join(sort(d.TXT), ","))
	return hex.EncodeToString(h.Sum(nil))[:16]
}

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
// BUG_FIX_CONTEXT: DaysRemaining defaults to -1 ("unknown"), NOT 0. The int zero-value read as
// "expires in 0 days = expired" whenever a zone omitted the expiry field, falsely flagging domains
// (e.g. RDAP-only .pro) as expired. Unknown expiry must never look like "already expired".
func parseWhoisFields(body string) WhoisInfo {
	wi := WhoisInfo{Status: "ok", DaysRemaining: -1}
	if m := reRegistrar.FindStringSubmatch(body); len(m) == 3 {
		wi.Registrar = strings.TrimSpace(m[2])
	}
	if m := reCreated.FindStringSubmatch(body); len(m) == 3 {
		wi.Created = strings.TrimSpace(m[2])
	}
	if m := reExpiry.FindStringSubmatch(body); len(m) == 3 {
		wi.Expiry = strings.TrimSpace(m[2])
		// Normalize to a bare date (2006-01-02) and compute days-until-expiry so the UI can render
		// "2026-08-22 (123d)" exactly like the certificate block. -1 when the registrar format is
		// unparseable (rare TLDs) — treated as "unknown expiry", not expired.
		if t, ok := parseExpiryDate(wi.Expiry); ok {
			wi.DaysRemaining = int(time.Until(t).Hours() / 24)
			wi.Expiry = t.UTC().Format("2006-01-02")
		} else {
			wi.DaysRemaining = -1
		}
	}
	if wi.Registrar == "" && wi.Created == "" && wi.Expiry == "" {
		wi.Status = "error"
		wi.Error = "no parseable registrar/created/expiry fields"
	}
	return wi
}
