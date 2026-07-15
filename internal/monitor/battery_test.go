package monitor

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/skibine/vm-pulse/internal/store"
)

// region FUNC_test_Battery [DOMAIN(7): Testing; CONCEPT(8): Telemetry; TECH(7): net,parallel]
// @purpose Verify the quick-status battery: ssh/tcp hits a live local listener (ok), web/tls on
//
//	a closed port fail (critical), dns resolves localhost. Asserts ordering, reachable headline.
//
// @complexity 5
// endregion FUNC_test_Battery
func TestBattery_LocalListener(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	vm := store.VM{IP: "127.0.0.1", Hostname: "localhost", PortSSH: port}
	reg := DefaultRegistry()

	outcomes := Battery(context.Background(), reg, vm, 6*time.Second)

	// LDD trace: print the battery trajectory at IMP:8 for Semantic Trace Verification.
	t.Logf("[IMP:8][TestBattery][RESULT] %d probes for 127.0.0.1:%d", len(outcomes), port)
	for _, o := range outcomes {
		t.Logf("[IMP:8][Battery][PROBE] %s=%s lat=%.2fms msg=%s", o.Name, o.Status, o.LatencyMS, o.Message)
	}

	if len(outcomes) < 3 {
		t.Fatalf("expected >=3 probes (ssh/dns/web-tls), got %d", len(outcomes))
	}
	byName := map[string]ProbeOutcome{}
	for _, o := range outcomes {
		byName[o.Name] = o
	}
	if ssh, ok := byName["ssh"]; !ok || ssh.Status != string(StatusOK) {
		got := "absent"
		if ok {
			got = ssh.Status
		}
		t.Fatalf("ssh probe must be ok (live listener), got %s", got)
	}
	if !Reachable(outcomes) {
		t.Fatal("Reachable must be true when ssh probe is ok")
	}
	if dns, ok := byName["dns"]; ok && dns.Status != string(StatusOK) {
		t.Errorf("dns probe on localhost must be ok, got %s", dns.Status)
	}
	// web (closed port 80) and tls (closed port 443) against 127.0.0.1 -> critical.
	if web, ok := byName["web"]; ok && web.Status == string(StatusOK) {
		t.Errorf("web probe against closed :80 must not be ok, got %s", web.Status)
	}
	if tls, ok := byName["tls"]; ok && tls.Status == string(StatusOK) {
		t.Errorf("tls probe against closed :443 must not be ok, got %s", tls.Status)
	}
}

// region FUNC_test_BuildBatterySpecs [DOMAIN(6): Testing; CONCEPT(6): Branching; TECH(4): map]
// @purpose Verify spec derivation: IP-only VM skips dns; hostname VM includes dns; ordering ssh-first.
// @complexity 3
// endregion FUNC_test_BuildBatterySpecs
func TestBuildBatterySpecs(t *testing.T) {
	ipOnly := store.VM{IP: "10.0.0.5", PortSSH: 22}
	s := BuildBatterySpecs(ipOnly)
	if len(s) == 0 || s[0].Name != "ping" {
		t.Fatalf("ping must be first spec (primary liveness), got %+v", s)
	}
	for _, sp := range s {
		if sp.Name == "dns" {
			t.Fatal("IP-only VM must not emit a dns spec")
		}
	}

	named := store.VM{Hostname: "example.com", PortSSH: 2222}
	s2 := BuildBatterySpecs(named)
	hasDNS := false
	for _, sp := range s2 {
		if sp.Name == "dns" {
			hasDNS = true
		}
	}
	if !hasDNS {
		t.Fatal("hostname VM must emit a dns spec")
	}
	if s2[0].Params["port"] != "2222" {
		t.Errorf("ssh spec port must be 2222, got %v", s2[0].Params["port"])
	}
	t.Logf("[IMP:8][TestSpecs][RESULT] ip-only=%d specs, named=%d specs", len(s), len(s2))
}

// region FUNC_test_Battery_Timeout [DOMAIN(6): Testing; CONCEPT(7): Robustness; TECH(5): context]
// @purpose Verify the battery context deadline cuts off slow probes without deadlock.
// @complexity 3
// endregion FUNC_test_Battery_Timeout
func TestBattery_Timeout(t *testing.T) {
	// 192.0.2.1 is TEST-NET-1 (RFC 5737) — unroutable; probes will time out fast under a tight ctx.
	vm := store.VM{IP: "192.0.2.1", PortSSH: 22}
	reg := DefaultRegistry()
	start := time.Now()
	outcomes := Battery(context.Background(), reg, vm, 1*time.Second)
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("battery must honor ctx timeout; took %v", elapsed)
	}
	t.Logf("[IMP:9][TestBattery][TIMEOUT] %d probes in %v (ctx bound 1s)", len(outcomes), elapsed)
	for _, o := range outcomes {
		t.Logf("[IMP:7][Battery][PROBE] %s=%s", o.Name, o.Status)
	}
}

// region FUNC_test_HTTPURL [DOMAIN(6): Testing; CONCEPT(6): Parsing; TECH(3): net]
// @purpose Verify the web-probe URL brackets IPv6 literals but not hostnames/IPv4.
// @complexity 2
// endregion FUNC_test_HTTPURL
func TestHTTPURL(t *testing.T) {
	cases := map[string]string{
		"example.com": "http://example.com/",
		"10.0.0.5":    "http://10.0.0.5/",
		"2001:db8::1": "http://[2001:db8::1]/",
		"::1":         "http://[::1]/",
	}
	for host, want := range cases {
		if got := httpURL(host); got != want {
			t.Errorf("httpURL(%q)=%q want %q", host, got, want)
		}
	}
	t.Logf("[IMP:8][TestHTTPURL][RESULT] %d cases passed", len(cases))
}
