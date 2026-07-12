package monitor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// region FUNC_test_SiteInfo_HeadersAndCMS [DOMAIN(7): Testing; CONCEPT(7]: SiteInfo; TECH(6]: httptest]
// @purpose Verify security-header capture/score and WordPress generator-meta fingerprint.
// @complexity 4
// endregion FUNC_test_SiteInfo_HeadersAndCMS
func TestSiteInfo_HeadersAndCMS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.Header().Set("X-Powered-By", "PHP/7.4")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2"></head></html>`))
	}))
	defer srv.Close()

	info, err := ProbeSite(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("SiteInfo: %v", err)
	}
	if info.Server != "nginx" || info.PoweredBy != "PHP/7.4" {
		t.Errorf("banners wrong: server=%q powered=%q", info.Server, info.PoweredBy)
	}
	if info.CMS != "wordpress" || info.CMSVersion != "6.4.2" {
		t.Errorf("cms fingerprint wrong: %s %s", info.CMS, info.CMSVersion)
	}
	if info.SecurityHeaders["Strict-Transport-Security"] == "" || info.SecurityHeaders["X-Frame-Options"] == "" {
		t.Errorf("security headers not captured: %+v", info.SecurityHeaders)
	}
	if info.SecurityHeaders["Content-Security-Policy"] != "" {
		t.Errorf("absent CSP must be empty string, got %q", info.SecurityHeaders["Content-Security-Policy"])
	}
	// 2 of 5 present -> 40
	if info.SecurityScore != 40 {
		t.Errorf("security score want 40, got %d", info.SecurityScore)
	}
	t.Logf("[IMP:8][TestSiteInfo][RESULT] cms=%s/%s score=%d server=%s", info.CMS, info.CMSVersion, info.SecurityScore, info.Server)
}

// region FUNC_test_SiteInfo_CMSPathProbe [DOMAIN(7): Testing; CONCEPT(7]: CMS; TECH(6]: httptest]
// @purpose When no generator meta is present, the WordPress login-path probe must confirm the CMS.
// @complexity 3
// endregion FUNC_test_SiteInfo_CMSPathProbe
func TestSiteInfo_CMSPathProbe(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/wp-login.php" {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	info, _ := ProbeSite(context.Background(), srv.URL)
	if info.CMS != "wordpress" {
		t.Fatalf("path probe must detect wordpress, got %q", info.CMS)
	}
	t.Logf("[IMP:8][TestSiteInfo][PROBE] cms via path=%s", info.CMS)
}
