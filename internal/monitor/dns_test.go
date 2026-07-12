// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: DNSChecker; TECH(8]: go test]
// @purpose Verify the DNS checker resolves a known host (localhost) and reports addrs + ok.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, dns, checker, resolve, localhost, addrs
package monitor

import (
	"context"
	"strings"
	"testing"
)

func TestDNSChecker_ResolvesLocalhost(t *testing.T) {
	res := DNSChecker{}.Run(context.Background(), "localhost", nil)
	if res.Status != StatusOK {
		t.Fatalf("localhost resolve: status=%s msg=%s", res.Status, res.Message)
	}
	// localhost must resolve to a loopback address on any sane test host.
	if !strings.Contains(res.Message, "127.0.0.1") && !strings.Contains(res.Message, "::1") {
		t.Fatalf("expected loopback in %q", res.Message)
	}
}

func TestDNSChecker_EmptyTarget(t *testing.T) {
	res := DNSChecker{}.Run(context.Background(), "  ", nil)
	if res.Status != StatusUnknown {
		t.Fatalf("empty target: status=%s want unknown", res.Status)
	}
}
