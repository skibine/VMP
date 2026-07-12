// Package monitor — site information: HTTP response headers + security posture + CMS fingerprint.
//
// region MODULE_CONTRACT [DOMAIN(8): Observability; CONCEPT(7): SiteInfo,CMS; TECH(8): net/http]
// @purpose Answer "what does this site run and how hardened is it?" — Server/X-Powered-By banner,
//
//	security-headers score, and CMS detection (WordPress/Drupal/Joomla/Ghost/Nextcloud) via the
//	generator meta + distinctive path probes. Credential-free (Plane A): a plain HTTP GET.
//
// @io (ctx, url) -> (SiteInfo, error)
// @invariants
//   - A fetch failure never panics; it returns FetchError so the UI can show the cause.
//   - Body read is capped (only the <head> region is needed for the generator meta).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: siteinfo, http headers, server banner, security headers, cms, wordpress, drupal, joomla, fingerprint
// STRUCTURE: ▶ ┌url┐ → ⚡ GET(follow redirects) → ⊕ headers + ◇ generator meta → ⊕ cms? probe paths → ⎋ SiteInfo
package monitor

import (
	"context"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// SiteInfo is the parsed website picture (headers + security + CMS).
type SiteInfo struct {
	URL             string            `json:"url"`
	FinalURL        string            `json:"final_url"`
	Redirected      bool              `json:"redirected"`
	Status          int               `json:"status"`
	Server          string            `json:"server"`
	PoweredBy       string            `json:"powered_by"`
	ContentType     string            `json:"content_type"`
	CMS             string            `json:"cms"`
	CMSVersion      string            `json:"cms_version"`
	SecurityHeaders map[string]string `json:"security_headers"`
	SecurityScore   int               `json:"security_score"`
	FetchError      string            `json:"fetch_error,omitempty"`
}

// securityHeaderKeys are the headers checked for the hardening score (presence-based).
var securityHeaderKeys = []string{
	"Strict-Transport-Security", // HSTS
	"Content-Security-Policy",   // CSP
	"X-Frame-Options",           // clickjacking
	"X-Content-Type-Options",    // MIME sniffing
	"Referrer-Policy",
}

// region FUNC_ProbeSite [DOMAIN(8): Observability; CONCEPT(7): SiteInfo; TECH(8): net/http]
// @purpose Fetch the URL, capture response headers + security posture, and fingerprint the CMS.
// @complexity 6
// endregion FUNC_ProbeSite
func ProbeSite(ctx context.Context, url string) (SiteInfo, error) {
	info := SiteInfo{URL: url, SecurityHeaders: map[string]string{}}
	client := &http.Client{Timeout: 8 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		info.FetchError = err.Error()
		return info, err
	}
	req.Header.Set("User-Agent", "VMPulse-SiteInfo/1.0")
	resp, err := client.Do(req)
	if err != nil {
		info.FetchError = err.Error()
		return info, err
	}
	defer resp.Body.Close()
	info.Status = resp.StatusCode
	info.FinalURL = resp.Request.URL.String()
	info.Redirected = !strings.EqualFold(info.FinalURL, url)
	info.Server = resp.Header.Get("Server")
	info.PoweredBy = resp.Header.Get("X-Powered-By")
	info.ContentType = resp.Header.Get("Content-Type")

	// Security headers: record presence/absence + the value when set.
	present := 0
	for _, k := range securityHeaderKeys {
		v := resp.Header.Get(k)
		if v != "" {
			info.SecurityHeaders[k] = v
			present++
		} else {
			info.SecurityHeaders[k] = ""
		}
	}
	info.SecurityScore = present * 100 / len(securityHeaderKeys)

	// Read up to 256KB of body (the <head>/generator meta is near the top) for CMS fingerprinting.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	detectCMSFromMeta(string(body), &info)
	// If the generator meta gave nothing, probe a couple of distinctive CMS endpoints.
	if info.CMS == "" {
		probeCMSPaths(ctx, url, &info)
	}
	return info, nil
}

var reGenerator = regexp.MustCompile(`(?i)<meta\s+name=["']?generator["']?\s+content=["']([^"']+)["']`)

// detectCMSFromMeta parses the <meta name="generator"> tag (WordPress/Drupal/Joomla/Ghost emit it).
func detectCMSFromMeta(body string, info *SiteInfo) {
	m := reGenerator.FindStringSubmatch(body)
	if len(m) != 2 {
		return
	}
	g := strings.TrimSpace(m[1])
	low := strings.ToLower(g)
	switch {
	case strings.HasPrefix(low, "wordpress"):
		info.CMS, info.CMSVersion = "wordpress", firstVersion(g)
	case strings.HasPrefix(low, "drupal"):
		info.CMS, info.CMSVersion = "drupal", firstVersion(g)
	case strings.HasPrefix(low, "joomla"):
		info.CMS, info.CMSVersion = "joomla", firstVersion(g)
	case strings.HasPrefix(low, "ghost"):
		info.CMS, info.CMSVersion = "ghost", firstVersion(g)
	}
}

// firstVersion extracts a leading x.y(.z) version token from a generator string like "WordPress 6.4.2".
func firstVersion(s string) string {
	for _, tok := range strings.Fields(s) {
		if _, err := strconv.ParseFloat(strings.SplitN(tok, ".", 2)[0], 64); err == nil {
			return tok
		}
	}
	return ""
}

// cmsPathProbes: distinctive, ordered endpoints (most specific first). A probe confirms a CMS when
// its status is in the set. Avoid generic paths like "/login" (too many false positives).
var cmsPathProbes = []struct {
	Path   string
	CMS    string
	Status map[int]struct{}
}{
	{"/wp-json/wp/v2/", "wordpress", map[int]struct{}{200: {}}},
	{"/wp-login.php", "wordpress", map[int]struct{}{200: {}, 302: {}}},
	{"/ocs/v1.php/cloud/capabilities", "nextcloud", map[int]struct{}{200: {}}},
	{"/administrator/", "joomla", map[int]struct{}{200: {}, 302: {}}},
	{"/user/login", "drupal", map[int]struct{}{200: {}}},
}

// probeCMSPaths sends light GET requests to distinctive CMS endpoints (in order) to confirm a CMS.
func probeCMSPaths(ctx context.Context, base string, info *SiteInfo) {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // do not follow; we inspect the direct status
	}}
	for _, p := range cmsPathProbes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+p.Path, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "VMPulse-SiteInfo/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		_, hit := p.Status[resp.StatusCode]
		_ = resp.Body.Close()
		if hit {
			info.CMS = p.CMS
			return
		}
	}
}
