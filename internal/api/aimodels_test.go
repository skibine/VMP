// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: AIModelDiscovery; TECH(8]: go test,httptest]
// @purpose Verify the AI model-discovery endpoints: GET /api/ai/models (provider /models proxy,
//
//	stored-key forwarding, tolerant parse) and GET /api/ai/probe-local (loopback LLM detection).
//	Prints [IMP:7-10] lines (Semantic Trace Verification).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, ai, models, probe, local, ollama, httptest, discovery
// STRUCTURE: ▶ ┌store + upstream┐ → ○ GET /models → 〈200? parse ids〉 → ⎋ assert
package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/skibine/vm-pulse/internal/store"
)

// TestAIModels_ProxyList stores a provider config pointing at a fake upstream and expects the
// proxy to forward the stored key and return the parsed model ids.
func TestAIModels_ProxyList(t *testing.T) {
	srv, buf := newServer(t)

	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/models" {
			t.Errorf("upstream path want /models, got %s", r.URL.Path)
		}
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"gpt-4o-mini","object":"model"},{"id":"gpt-4o","object":"model"}]}`))
	}))
	t.Cleanup(upstream.Close)

	// Seed stored config (api_url = upstream, key forwarded server-side).
	if err := srv.store.SetAIConfig(t.Context(), store.AIConfig{APIURL: upstream.URL, APIKey: "sk-test"}); err != nil {
		t.Fatalf("SetAIConfig: %v", err)
	}

	rec := do(srv, http.MethodGet, "/api/ai/models", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if gotAuth != "Bearer sk-test" {
		t.Fatalf("stored key not forwarded: got %q", gotAuth)
	}
	var body struct {
		Models []string `json:"models"`
	}
	decode(t, rec, &body)
	if len(body.Models) != 2 || body.Models[0] != "gpt-4o-mini" || body.Models[1] != "gpt-4o" {
		t.Fatalf("unexpected models: %+v", body.Models)
	}
	printIMPFromBuf(t, buf)
}

// TestAIModels_NotConfigured expects a 400 (distinct from a bad provider's 502) when no api_url is set.
func TestAIModels_NotConfigured(t *testing.T) {
	srv, _ := newServer(t)
	rec := do(srv, http.MethodGet, "/api/ai/models", "")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400 for unconfigured provider, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestAIModels_UpstreamError expects a 502 when the provider responds non-2xx.
func TestAIModels_UpstreamError(t *testing.T) {
	srv, _ := newServer(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	t.Cleanup(upstream.Close)

	if err := srv.store.SetAIConfig(t.Context(), store.AIConfig{APIURL: upstream.URL, APIKey: "sk-bad"}); err != nil {
		t.Fatalf("SetAIConfig: %v", err)
	}
	rec := do(srv, http.MethodGet, "/api/ai/models", "")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("want 502 on upstream error, got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestProbeLocal repoints the loopback targets at two httptest servers (one alive, one 500ing)
// and asserts the alive flag + returned model ids.
func TestProbeLocal(t *testing.T) {
	srv, buf := newServer(t)

	alive := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"llama3.1"},{"id":"qwen2.5"}]}`))
	}))
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(alive.Close)
	t.Cleanup(dead.Close)

	orig := localLLMTargets
	localLLMTargets = []localLLMTarget{
		{ID: "mock-ok", Label: "Mock OK", BaseURL: alive.URL},
		{ID: "mock-bad", Label: "Mock Bad", BaseURL: dead.URL},
	}
	t.Cleanup(func() { localLLMTargets = orig })

	rec := do(srv, http.MethodGet, "/api/ai/probe-local", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Targets []struct {
			ID     string   `json:"id"`
			Alive  bool     `json:"alive"`
			Models []string `json:"models"`
		} `json:"targets"`
	}
	decode(t, rec, &body)
	if len(body.Targets) != 2 {
		t.Fatalf("want 2 targets, got %d", len(body.Targets))
	}
	byID := map[string]struct {
		Alive  bool
		Models []string
	}{}
	for _, tg := range body.Targets {
		byID[tg.ID] = struct {
			Alive  bool
			Models []string
		}{tg.Alive, tg.Models}
	}
	if !byID["mock-ok"].Alive || len(byID["mock-ok"].Models) != 2 {
		t.Fatalf("mock-ok want alive+2 models, got %+v", byID["mock-ok"])
	}
	if byID["mock-bad"].Alive || byID["mock-bad"].Models != nil {
		t.Fatalf("mock-bad want dead+nil models, got %+v", byID["mock-bad"])
	}
	printIMPFromBuf(t, buf)
}

// TestFetchModelIDs_Empty ensures a 2xx response with no data yields an empty slice, not an error.
func TestFetchModelIDs_Empty(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
	}))
	t.Cleanup(upstream.Close)
	ids, err := fetchModelIDs(t.Context(), upstream.URL, "local")
	if err != nil {
		t.Fatalf("empty list should not error, got %v", err)
	}
	if len(ids) != 0 {
		t.Fatalf("want 0 ids, got %v", ids)
	}
}
