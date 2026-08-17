// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8]: RegistryIPBlock; TECH(8]: go test,net]
// @purpose Reproduce the home-IP failure captured from the operator's machine: the registry whois
//
//	server ACCEPTS the TCP connection and immediately RSTs it (verified live for whois.nic.top).
//	In Go that reads as an EMPTY body with nil error. The lookup must (a) NOT leak the IANA
//	referral's TLD-level data as domain data, (b) fall through to RDAP and get rescued by the
//	port-443 redirector with real registration data.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, registry ip block, connection reset, empty whois body, iana leak, rdap rescue
// STRUCTURE: ▶ ┌fake IANA (refer) + fake registry (accept+RST) + fake rdap.org┐ → ○ whoisLookup → 〈no leak? rescued?〉 → ⎋
package monitor

import (
	"bufio"
	"context"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeIANA answers with a referral to the fake registry for any query.
func fakeIANA(t *testing.T, registryHostPort string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			_, _ = bufio.NewReader(c).ReadString('\n')
			_, _ = c.Write([]byte("refer: " + registryHostPort + "\ndomain: TOP\ncreated: 2014-07-24\n\n"))
			_ = c.Close()
		}
	}()
	ianaAddr = ln.Addr().String()
	t.Cleanup(func() { ianaAddr = "whois.iana.org:43" })
}

// fakeRegistryIPBlock accepts the TCP connection and immediately RSTs it (the operator's case).
func fakeRegistryIPBlock(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			if tc, ok := c.(*net.TCPConn); ok {
				// SetLinger(0) => RST on Close: exactly "remote host forcibly closed the connection".
				_ = tc.SetLinger(0)
			}
			_ = c.Close()
		}
	}()
	return ln.Addr().String()
}

// startFakeRDAP serves a minimal RDAP object for any /domain/{name} query.
func startFakeRDAP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 1024)
			_, _ = c.Read(buf)
			body := `{"events":[{"eventAction":"registration","eventDate":"2025-08-22T17:49:25Z"},
{"eventAction":"expiration","eventDate":"2030-01-01T00:00:00Z"}],
"entities":[{"roles":["registrar"],"vcardArray":["vcard",[["fn",{},"text","NameSilo,LLC"]]]}]}`
			resp := "HTTP/1.1 200 OK\r\nContent-Type: application/rdap+json\r\nContent-Length: " +
				strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
			_, _ = c.Write([]byte(resp))
			_ = c.Close()
		}
	}()
	return "http://" + ln.Addr().String()
}

func TestWhoisLookup_RegistryIPBlock_RdapRescue(t *testing.T) {
	regAddr := fakeRegistryIPBlock(t)
	fakeIANA(t, regAddr)

	// Rescue path: point the RDAP fallback at a fake redirector serving real-shaped data.
	savedBase := rdapFallbackBase
	rdapFallbackBase = startFakeRDAP(t)
	t.Cleanup(func() { rdapFallbackBase = savedBase })
	// Make the OFFICIAL bootstrap path fail so the redirector is the one answering.
	savedBoot := rdapBootstrapURL
	rdapBootstrapURL = "http://127.0.0.1:1/none.json"
	rdapCacheMu.Lock()
	rdapCache, rdapCachedAt = nil, time.Time{}
	rdapCacheMu.Unlock()
	t.Cleanup(func() {
		rdapBootstrapURL = savedBoot
		rdapCacheMu.Lock()
		rdapCache, rdapCachedAt = nil, time.Time{}
		rdapCacheMu.Unlock()
	})

	wi, err := whoisLookup(context.Background(), "example.top")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	// (a) The IANA referral body must NOT leak as domain data (TLD created 2014 must be gone).
	if wi.Created == "2014-07-24" {
		t.Fatalf("IANA TLD data leaked into the domain record: %+v", wi)
	}
	// (b) RDAP rescued the blocked-registry lookup with real data.
	if wi.Expiry != "2030-01-01" || wi.Status != "ok" {
		t.Fatalf("rdap rescue failed: %+v", wi)
	}
	if !strings.Contains(wi.Registrar, "NameSilo") {
		t.Fatalf("registrar from rdap missing: %+v", wi)
	}
	t.Logf("[IMP:9][TestIPBlock][RESULT] no-leak ok, rescued expiry=%s registrar=%s", wi.Expiry, wi.Registrar)
}
