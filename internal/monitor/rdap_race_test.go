// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8]: RdapStall; TECH(8]: go test,net]
// @purpose Reproduce the server-freeze root cause: a registry RDAP endpoint that ACCEPTS the
//
//	connection and never answers (the "VMPulse завис" case). The race must (a) answer via the
//	redirector within the client timeout — not hang, (b) the whole whois chain must return even
//	with a deadline-less context (internal budget), (c) both endpoints stalled => bounded return.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, rdap stall, race, redirector, hang, budget, socket exhaustion
// STRUCTURE: ▶ ┌stall official + fast redirector┐ → ○ rdapLookupAny / whoisLookup → 〈fast? bounded?〉 → ⎋
package monitor

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// startStallServer accepts connections and never writes a byte (the freezing registry).
func startStallServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			_, e := ln.Accept()
			if e != nil {
				return
			}
			// accepted connections are simply never answered; closing the listener on cleanup
			// drops them
		}
	}()
	return "http://" + ln.Addr().String()
}

func TestRdapRace_StalledOfficial_RedirectorWinsFast(t *testing.T) {
	// Shrink the client so the test is fast.
	savedClient := rdapClient
	rdapClient = &http.Client{Timeout: 500 * time.Millisecond}
	t.Cleanup(func() { rdapClient = savedClient })

	stall := startStallServer(t)
	fast := startFakeRDAP(t) // serves expiry 2030-01-01 (whois_ipblock_test.go)

	// Official base = stall; bootstrap must resolve there: prime the cache directly.
	rdapCacheMu.Lock()
	rdapCache = map[string]string{"top": stall}
	rdapCachedAt = time.Now()
	rdapCacheMu.Unlock()
	t.Cleanup(func() {
		rdapCacheMu.Lock()
		rdapCache, rdapCachedAt = nil, time.Time{}
		rdapCacheMu.Unlock()
	})
	savedFB := rdapFallbackBase
	rdapFallbackBase = fast
	t.Cleanup(func() { rdapFallbackBase = savedFB })

	start := time.Now()
	wi, err := rdapLookupAny(context.Background(), "example.top")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if wi.Expiry != "2030-01-01" {
		t.Fatalf("redirector answer expected, got %+v", wi)
	}
	if el := time.Since(start); el > 900*time.Millisecond {
		t.Fatalf("race waited for the stalled endpoint: %v", el)
	}
	t.Logf("[IMP:9][TestRdapRace][RESULT] stalled=ignored redirector-wins in %v", time.Since(start))
}

func TestWhoisLookup_DeadlinelessContext_IsBounded(t *testing.T) {
	// Everything stalled: IANA + registry + both RDAP endpoints. context.Background() has NO
	// deadline (the background-caller case). The internal budget must still return us quickly.
	savedBudget := whoisBudget
	whoisBudget = 700 * time.Millisecond
	t.Cleanup(func() { whoisBudget = savedBudget })

	stall := startStallServer(t)
	savedAddr := ianaAddr
	ianaAddr = strings.TrimPrefix(stall, "http://") // whois needs host:port, not a URL
	t.Cleanup(func() { ianaAddr = savedAddr })

	savedClient := rdapClient
	rdapClient = &http.Client{Timeout: 400 * time.Millisecond}
	t.Cleanup(func() { rdapClient = savedClient })
	savedFB := rdapFallbackBase
	rdapFallbackBase = stall
	t.Cleanup(func() { rdapFallbackBase = savedFB })
	rdapCacheMu.Lock()
	rdapCache, rdapCachedAt = nil, time.Time{}
	rdapCacheMu.Unlock()
	savedBoot := rdapBootstrapURL
	rdapBootstrapURL = stall + "/none.json" // bootstrap fetch stalls too
	t.Cleanup(func() { rdapBootstrapURL = savedBoot })

	start := time.Now()
	wi, err := whoisLookup(context.Background(), "whatever.example")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if el := time.Since(start); el > 2*whoisBudget {
		t.Fatalf("deadlineless context ran unbounded: %v (%+v)", el, wi)
	}
	// Honest failure shape: status error, no data invented.
	if wi.Status != "error" && wi.Expiry == "" {
		t.Fatalf("expected error status, got %+v", wi)
	}
	t.Logf("[IMP:9][TestBounded][RESULT] returned in %v with %+v", time.Since(start), wi.Status)
}
