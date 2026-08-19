// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): SSRFGuard; TECH(8): go test,httptest]
// @purpose Verify the SSRF choke point: metadata targets refused (URL check + dial control +
//
//	redirect re-check), private/loopback deliberately allowed (LAN equipment monitoring).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, ssrf, metadata, 169.254.169.254, redirect, dial control, safe client
package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// region FUNC_test_SSRF_Blocked [DOMAIN(8): Security; CONCEPT(7): MetadataBlock; TECH(6): table]
// @purpose URL-level guards: scheme + metadata hostname refused; normal hosts pass.
// @complexity 2
// endregion FUNC_test_SSRF_Blocked
func TestSSRF_CheckTargetURL(t *testing.T) {
	blocked := []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/", // Alibaba metadata (CGNAT range)
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://metadata/",              // Azure short name
		"file:///etc/passwd",            // scheme guard
		"gopher://169.254.169.254:70/x", // exotic scheme
	}
	for _, u := range blocked {
		if err := CheckTargetURL(u); err == nil {
			t.Fatalf("must be blocked: %s", u)
		}
	}
	allowed := []string{"http://example.com/", "https://192.168.1.1/", "http://127.0.0.1:8080/"}
	for _, u := range allowed {
		if err := CheckTargetURL(u); err != nil {
			t.Fatalf("must be allowed (LAN/loopback monitoring is a feature): %s: %v", u, err)
		}
	}
	t.Logf("[IMP:8][TestSSRF][RESULT] url-guard ok: metadata+scheme blocked, private allowed")
}

// region FUNC_test_SSRF_HostBlocked [DOMAIN(8): Security; CONCEPT(7): ResolveCheck; TECH(6): table]
// @purpose Resolve-level guard (webhook path): metadata IPs and names blocked.
// @complexity 2
// endregion FUNC_test_SSRF_HostBlocked
func TestSSRF_HostBlocked(t *testing.T) {
	for _, h := range []string{"169.254.169.254", "100.100.100.200", "metadata.google.internal", "metadata", "fd00:ec2::254"} {
		if !HostBlocked(h) {
			t.Fatalf("must be blocked: %s", h)
		}
	}
	if HostBlocked("example.com") {
		t.Fatal("example.com must not be blocked")
	}
	if HostBlocked("127.0.0.1") || HostBlocked("192.168.1.1") {
		t.Log("[IMP:7][TestSSRF][NOTE] loopback/private blocked at HostBlocked level (webhook-strict); fetch path allows them")
	}
	t.Logf("[IMP:8][TestSSRF][RESULT] resolve-guard ok")
}

// region FUNC_test_SSRF_DialControl [DOMAIN(8): Security; CONCEPT(8): DialBlock; TECH(7): httptest]
// @purpose The dial-time Control refuses a DIRECT metadata fetch even when the URL check passed
//
//	(numeric IP), and a REDIRECT chain ending at a metadata address is cut at the re-dial.
//
// @complexity 4
// endregion FUNC_test_SSRF_DialControl
func TestSSRF_DialAndRedirectBlocked(t *testing.T) {
	c := SafeClient(3 * time.Second)

	// Direct dial to the metadata IP: URL check passes (no name), dial control must refuse.
	_, err := c.Get("http://169.254.169.254/")
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("direct metadata dial must be refused with 'blocked', got: %v", err)
	}

	// Redirect chain: benign local server 302 -> metadata IP. The hop re-dials -> refused.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	}))
	defer srv.Close()
	_, err = c.Get(srv.URL)
	if err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("redirect-to-metadata must be refused at re-dial, got: %v", err)
	}

	// Sanity: a normal local fetch through SafeClient still works (loopback allowed by design).
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer ok.Close()
	resp, err := c.Get(ok.URL)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("normal fetch broken: %v", err)
	}
	_ = resp.Body.Close()
	t.Logf("[IMP:9][TestSSRF][RESULT] dial+redirect metadata blocked, normal fetch intact")
	_ = context.Background()
}

// endregion FUNC_test_SSRF_DialControl
