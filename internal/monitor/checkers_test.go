// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): Checkers; TECH(8): go test,net,httptest]
// @purpose Verify each checker against local/httptest fixtures (no external network).
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, checkers, tcp, http, tls, whois, ping, httptest
// STRUCTURE: ▶ ┌fixture┐ → ○ Checker.Run → 〈status/latency/detail〉 → ⎋ assert
package monitor

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/skibine/vmp/internal/lddcheck"
	"github.com/skibine/vmp/internal/logging"
)

func testLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return logging.Setup(slog.LevelDebug, &buf), &buf
}

func printIMP(t *testing.T, buf *bytes.Buffer, anchor string) {
	t.Helper()
	out := buf.String()
	t.Log("--- LDD TRAJECTORY (IMP:7-10) ---")
	saw := false
	for _, line := range strings.Split(out, "\n") {
		if imp, ok := lddcheck.IMPValue(line); ok && imp >= 7 {
			t.Log(line)
			saw = true
		}
	}
	_ = saw
	if anchor != "" && !strings.Contains(out, anchor) {
		t.Errorf("Anti-Illusion: missing anchor %q in logs", anchor)
	}
}

func hostPort(addr string) (string, string) {
	h, p, _ := net.SplitHostPort(addr)
	return h, p
}

func TestTCPChecker_OkAndFail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			_ = c.Close()
		}
	}()
	host, port := hostPort(ln.Addr().String())
	ctx := context.Background()

	res := TCPChecker{}.Run(ctx, host, map[string]any{"port": port})
	if res.Status != StatusOK {
		t.Fatalf("open port want ok, got %s (%s)", res.Status, res.Message)
	}
	if res.LatencyMS <= 0 {
		t.Fatalf("expected positive latency, got %v", res.LatencyMS)
	}

	// Closed port (reuse the now-not-listening high port by picking a likely-closed one).
	res = TCPChecker{}.Run(ctx, "127.0.0.1", map[string]any{"port": "1", "timeout_sec": 1.0})
	if res.Status != StatusCritical {
		t.Fatalf("closed port want critical, got %s", res.Status)
	}
}

func TestHTTPChecker_StatusCodes(t *testing.T) {
	srv200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv200.Close()
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv500.Close()
	ctx := context.Background()

	if res := (HTTPChecker{}).Run(ctx, "", map[string]any{"url": srv200.URL}); res.Status != StatusOK {
		t.Fatalf("200 want ok, got %s", res.Status)
	}
	if res := (HTTPChecker{}).Run(ctx, "", map[string]any{"url": srv500.URL}); res.Status != StatusCritical {
		t.Fatalf("500 want critical, got %s", res.Status)
	}
	// expect_status override.
	if res := (HTTPChecker{}).Run(ctx, "", map[string]any{"url": srv500.URL, "expect_status": 500}); res.Status != StatusOK {
		t.Fatalf("expect 500 want ok, got %s", res.Status)
	}
}

func TestTLSChecker_InsecureHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, port := hostPort(srv.Listener.Addr().String())
	ctx := context.Background()

	res := TLSChecker{}.Run(ctx, host, map[string]any{"port": port, "insecure": true})
	if res.Status == StatusCritical {
		t.Fatalf("insecure handshake should succeed, got critical: %s", res.Message)
	}
	if res.Detail["not_after"] == nil {
		t.Fatalf("expected not_after in detail: %#v", res.Detail)
	}
}

func TestWhoisChecker_LocalServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, e := ln.Accept()
			if e != nil {
				return
			}
			buf := make([]byte, 256)
			_, _ = c.Read(buf)
			_, _ = c.Write([]byte("Domain: example.com\nRegistry Expiry Date: 2030-01-01\n"))
			_ = c.Close()
		}
	}()
	_, port := hostPort(ln.Addr().String())
	ctx := context.Background()

	res := WhoisChecker{}.Run(ctx, "example.com", map[string]any{"server": "127.0.0.1", "port": port})
	if res.Status != StatusOK {
		t.Fatalf("whois want ok, got %s (%s)", res.Status, res.Message)
	}
	if res.Detail["has_expiry"] != true {
		t.Fatalf("expected has_expiry=true: %#v", res.Detail)
	}
}

func TestPingChecker_NoPanic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	// Privilege-dependent: assert only that it returns a valid status without panicking.
	res := PingChecker{}.Run(ctx, "127.0.0.1", nil)
	switch res.Status {
	case StatusOK, StatusUnknown, StatusCritical:
		// acceptable
	default:
		t.Fatalf("unexpected status %q", res.Status)
	}
}
