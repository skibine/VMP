// Package monitor — SSRF-safe outbound HTTP (shared guard for all fetch paths).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): SSRF; TECH(8): net/http,dial-control]
// @purpose Single choke point for every outbound HTTP fetch VM Pulse performs (http checks,
//
//	siteinfo, AI tools): block cloud-metadata endpoints at DIAL time so redirects and
//	DNS-rebinding cannot绕过 the URL-time check, while KEEPING loopback/private ranges usable -
//	monitoring LAN equipment (routers, cameras at 192.168.x) is a core product feature.
//
// @io SafeClient(timeout) -> *http.Client ; CheckTargetURL(raw) -> error ; ResolvePrivate(host) -> bool
// @invariants
//   - Link-local (169.254.0.0/16, fe80::/10) and EC2 IPv6 metadata (fd00:ec2::254) are REFUSED
//     at dial time on EVERY hop (redirects re-dial through the same Transport).
//   - Known metadata hostnames (metadata.google.internal et al.) are refused at URL check.
//   - Loopback/private/unspecified addresses are ALLOWED (operator monitors their own LAN);
//     this is a product decision, not an oversight.
//   - Only http/https schemes are fetchable; the transport is created once per client.
//
// @rationale
// Q: Why dial-time Control instead of URL-time resolve checks?
// A: A URL-time check is TOCTOU-racy (DNS rebinding: resolve public, connect private) and
// blind to redirects. net.Dialer.Control fires with the ACTUAL address right before connect
// on every hop - nothing can slip past it.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: ssrf, safe http, metadata endpoint, 169.254.169.254, dial control, redirect, dns rebinding
// STRUCTURE: ▶ ┌url┐ → ○ scheme/host check → ⚡ Transport(Dialer.Control ⊖metadata) → ⊕ redirects re-guarded → ⎷ resp
package monitor

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"
)

// metadataHostnames are well-known cloud metadata endpoints refused by name (resolve-time IP
// checks below catch their addresses too; this list catches them before any DNS query).
var metadataHostnames = map[string]bool{
	"metadata":                 true, // Azure's short name
	"metadata.google.internal": true,
}

// isMetadataIP reports whether the address belongs to a cloud-metadata range.
func isMetadataIP(ip net.IP) bool {
	if ip.To4() != nil {
		// 169.254.0.0/16 link-local: home of 169.254.169.254 (AWS/GCP/Azure/OpenStack metadata).
		return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
	}
	// fe80::/10 link-local + fd00:ec2::254 (AWS IMDS IPv6 endpoint).
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		strings.EqualFold(ip.String(), "fd00:ec2::254")
}

// HostBlocked reports whether a hostname (or IP literal) resolves (or equals) a blocked
// metadata target. Public API for callers that validate URLs they do not fetch themselves
// (webhook channel config).
func HostBlocked(host string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" || metadataHostnames[host] {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return isMetadataIP(ip)
	}
	// Resolve and check every address (a hostname that resolves to ANY blocked IP is refused).
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return false // unresolvable hosts fail later at fetch; do not double-punish
	}
	for _, ip := range ips {
		if isMetadataIP(ip.IP) {
			return true
		}
	}
	return false
}

// guardControl is the net.Dialer.Control hook: the last word before any TCP connect.
func guardControl(network, addr string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("safehttp: bad dial addr %q", addr)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("safehttp: non-IP dial addr %q", addr)
	}
	if isMetadataIP(ip) {
		return fmt.Errorf("safehttp: blocked cloud-metadata address %s", ip)
	}
	return nil
}

// CheckTargetURL validates a fetch target BEFORE any client work: http/https scheme,
// host not a known metadata name. (Address ranges are enforced at dial time - see guardControl.)
func CheckTargetURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("safehttp: bad url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("safehttp: scheme %q not allowed", u.Scheme)
	}
	host := strings.ToLower(u.Hostname())
	if metadataHostnames[host] {
		return fmt.Errorf("safehttp: metadata hostname %q not allowed", u.Hostname())
	}
	// Numeric IP literals are checked here too (defense in depth; the dial control re-checks).
	if ip := net.ParseIP(host); ip != nil && isMetadataIP(ip) {
		return fmt.Errorf("safehttp: metadata address %q not allowed", host)
	}
	return nil
}

// region FUNC_SafeClient [DOMAIN(9): Security; CONCEPT(7): GuardedFetch; TECH(8): net/http]
// @purpose Build an HTTP client whose EVERY dial (initial + redirects) is refused for
//
//	cloud-metadata addresses. Loopback/private stay allowed (LAN equipment monitoring).
//
// @complexity 4
// endregion FUNC_SafeClient
func SafeClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second, Control: guardControl}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext:         dialer.DialContext,
			ForceAttemptHTTP2:   false,
			MaxIdleConns:        4,
			IdleConnTimeout:     30 * time.Second,
			DisableKeepAlives:   false,
			TLSHandshakeTimeout: 5 * time.Second,
		},
	}
}
