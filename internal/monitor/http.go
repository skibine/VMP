// Package monitor — HTTP checker.
//
// region MODULE_CONTRACT [DOMAIN(7): Monitoring; CONCEPT(7): HTTPProbe; TECH(8): net/http]
// @purpose GET a URL and report status from the response code; optional expect_status param.
// @invariants
//   - Without expect_status: 2xx/3xx -> ok, 4xx/5xx -> critical.
//   - With expect_status: only that exact code -> ok, else critical.
//   - Network error / timeout -> critical.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: http, checker, GET, status code, expect_status, latency
// STRUCTURE: ▶ ┌url┐ → ○ NewRequestWithContext → ⚡ client.Do → 〈code match?〉 → ⊕ Result
package monitor

import (
	"context"
	"net/http"
	"time"
)

// region STRUCT_HTTPChecker [DOMAIN(7): Monitoring; CONCEPT(6): Plugin; TECH(8): net/http]
// @purpose HTTP reachability + status-code checker.
// endregion STRUCT_HTTPChecker
type HTTPChecker struct{}

func (HTTPChecker) Type() string { return "http" }

// region FUNC_HTTPChecker_Run [DOMAIN(7): Monitoring; CONCEPT(7): Probe; TECH(8): net/http]
// @purpose Fetch the URL and evaluate the response code.
// @complexity 5
// endregion FUNC_HTTPChecker_Run
func (HTTPChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	url := strOf(params, "url", "http://"+target+"/")
	timeout := timeoutOf(params, 5*time.Second)
	expect := intOf(params, "expect_status", 0)
	client := &http.Client{Timeout: timeout}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Result{Status: StatusCritical, Message: "bad url: " + err.Error(),
			Detail: map[string]any{"url": url}}
	}
	start := time.Now()
	resp, err := client.Do(req)
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return Result{Status: StatusCritical, LatencyMS: latency, Message: err.Error(),
			Detail: map[string]any{"url": url}}
	}
	defer resp.Body.Close()

	status := StatusOK
	switch {
	case expect > 0 && resp.StatusCode != expect:
		status = StatusCritical
	case expect == 0 && (resp.StatusCode < 200 || resp.StatusCode >= 400):
		status = StatusCritical
	}
	return Result{Status: status, LatencyMS: latency, Message: resp.Status,
		Detail: map[string]any{"url": url, "code": resp.StatusCode}}
}
