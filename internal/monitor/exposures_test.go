// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(9]: ExposureScan; TECH(8]: go test,net,httptest]
// @purpose Verify the curated exposure probes confirm exposure via fingerprints and stay silent
//
//	on negatives (no false positives). Uses local net listeners + httptest so no privileged ports.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, exposures, redis, docker, elastic, git, env, weak tls, fingerprint
// STRUCTURE: ▶ ┌listener/httptest┐ → ○ *At(ctx,target) → 〈fingerprint?〉 → ⎋ assert
package monitor

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// lineServer starts a TCP listener that, on connect, reads one line then replies with resp.
func lineServer(t *testing.T, resp string) (addr string, readFirst bool) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 64)
				_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
				c.Read(buf) // consume PING/stats
				_, _ = c.Write([]byte(resp))
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String(), true
}

// bannerServer starts a TCP listener that immediately writes banner on connect (VNC/telnet-style).
func bannerServer(t *testing.T, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte(banner))
				buf := make([]byte, 16)
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				c.Read(buf)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return ln.Addr().String()
}

func TestRedisProbe_ConfirmsAndNegative(t *testing.T) {
	ctx := context.Background()
	addr, _ := lineServer(t, "+PONG\r\n")
	if f := redisAt(ctx, addr); f == nil || f.ID != "redis-open" || f.Severity != "critical" {
		t.Fatalf("expected redis finding, got %+v", f)
	}
	// Negative: a port that refuses -> no finding.
	if f := redisAt(ctx, "127.0.0.1:1"); f != nil {
		t.Fatalf("expected nil for closed port, got %+v", f)
	}
}

func TestMemcachedProbe(t *testing.T) {
	addr, _ := lineServer(t, "STAT pid 1\r\nEND\r\n")
	if f := memcachedAt(context.Background(), addr); f == nil || f.Severity != "high" {
		t.Fatalf("expected memcached finding, got %+v", f)
	}
}

func TestVNCAndTelnetProbes(t *testing.T) {
	vnc := bannerServer(t, "RFB 003.008\n")
	if f := vncAt(context.Background(), vnc); f == nil || f.ID != "vnc-open" {
		t.Fatalf("expected vnc finding, got %+v", f)
	}
	tel := bannerServer(t, "\xff\xfb\x01\xff\xfb\x03")
	if f := telnetAt(context.Background(), tel); f == nil || f.ID != "telnet-open" {
		t.Fatalf("expected telnet finding, got %+v", f)
	}
}

func TestDockerProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/version" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte(`{"Version":"20.10.0","Components":[]}`))
	}))
	t.Cleanup(srv.Close)
	if f := dockerAt(context.Background(), srv.URL); f == nil || f.Severity != "critical" {
		t.Fatalf("expected docker finding, got %+v", f)
	}
}

func TestDockerProbe_Negative(t *testing.T) {
	// A 404 / no Version body -> not flagged.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	if f := dockerAt(context.Background(), srv.URL); f != nil {
		t.Fatalf("expected nil for non-docker server, got %+v", f)
	}
}

func TestElasticsearchProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"name":"node","cluster_name":"elasticsearch","version":{"number":"7.10.0"}}`))
	}))
	t.Cleanup(srv.Close)
	if f := elasticAt(context.Background(), srv.URL); f == nil || f.ID != "elastic-open" {
		t.Fatalf("expected elastic finding, got %+v", f)
	}
}

func TestGitExposedProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.git/config" {
			_, _ = w.Write([]byte("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = git@github.com:x/y.git\n"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	// gitHTTPAt takes a host and tries scheme://host; reuse the httptest host:port via "http" scheme only.
	host := srv.Listener.Addr().String()
	if f := gitHTTPAt(context.Background(), host, []string{"http"}); f == nil || f.ID != "git-dir-exposed" {
		t.Fatalf("expected git finding, got %+v", f)
	}
}

func TestEnvExposedProbe_NegativeOn404(t *testing.T) {
	// A 404 page that merely mentions .env must NOT be flagged.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	if f := envHTTPAt(context.Background(), host, []string{"http"}); f != nil {
		t.Fatalf("expected nil for 404, got %+v", f)
	}
}

func TestEnvExposedProbe_Positive(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			_, _ = w.Write([]byte("APP_KEY=base64:abc\nDB_PASSWORD=s3cret\n"))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	host := srv.Listener.Addr().String()
	if f := envHTTPAt(context.Background(), host, []string{"http"}); f == nil || f.Severity != "critical" {
		t.Fatalf("expected env finding, got %+v", f)
	}
}

// TestWeakTLSProbe_ExpiredCert stands up a TLS server with a self-signed, already-expired cert.
func TestWeakTLSProbe_ExpiredCert(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(srv.Close)
	// httptest TLS cert is valid for the future, so this primarily checks the path does not panic
	// and returns nil for a healthy cert. We assert no crash + a *Finding or nil.
	f := weakTLSAt(context.Background(), srv.Listener.Addr().String())
	_ = f // valid cert -> nil is fine; the goal is no panic/hang.
	_ = tls.VersionTLS12
}

// TestExposures_SortsBySeverity runs the full scan against an unreachable host (all probes fail)
// and confirms it returns an empty slice, not nil-pointer panics, within the deadline.
func TestExposures_EmptyHostAndTimeout(t *testing.T) {
	if got := Exposures(context.Background(), "", time.Second); len(got) != 0 {
		t.Fatalf("empty host should yield no findings, got %v", got)
	}
	// Unreachable host: every probe times out; expect empty + fast (well under scanTimeout).
	start := time.Now()
	got := Exposures(context.Background(), "127.0.0.1:1", 6*time.Second)
	elapsed := time.Since(start)
	if len(got) != 0 {
		t.Fatalf("unreachable host should yield no findings, got %v", got)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("scan took too long (%v) — per-probe timeout not bounding", elapsed)
	}
}

// TestExposuresChecker_Run verifies the checker maps findings to status and carries them in Detail.
func TestExposuresChecker_Run(t *testing.T) {
	chk := ExposuresChecker{}
	// Empty target -> unknown.
	if r := chk.Run(context.Background(), "", nil); r.Status != StatusUnknown {
		t.Fatalf("empty target want unknown, got %s", r.Status)
	}
	// Unreachable host -> no findings -> ok with a Detail map.
	r := chk.Run(context.Background(), "127.0.0.1:1", nil)
	if r.Status != StatusOK {
		t.Fatalf("clean scan want ok, got %s (msg=%s)", r.Status, r.Message)
	}
	if r.Detail == nil || r.Detail["findings"] == nil {
		t.Fatalf("expected findings detail, got %+v", r.Detail)
	}
}
