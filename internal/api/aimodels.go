// Package api — AI model discovery: provider /models proxy + local LLM detection.
//
// region MODULE_CONTRACT [DOMAIN(9): AI; CONCEPT(8): ModelDiscovery; TECH(8): net/http]
// @purpose Let the Settings UI populate the model field by listing models from the configured
//
//	OpenAI-compatible provider (GET /models), and detect which local LLM servers (Ollama /
//	LM Studio / vLLM) are running on the VMPulse host. Backend proxy avoids browser CORS and
//	keeps the API key server-side (the key never round-trips through the browser).
//
// @io GET /api/ai/models -> {models:[id]} ; GET /api/ai/probe-local -> {targets:[{id,label,alive,models}]}
// @invariants
//   - aiModels sends the stored key ONLY to the configured api_url.
//   - probeLocalAI dials ONLY 127.0.0.1 loopback targets.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: ai, models, openai-compatible, ollama, lmstudio, vllm, probe, local, discovery
// STRUCTURE: ▶ ┌stored cfg / loopback targets┐ → ○ GET /models → 〈parse data[].id〉 → ⊕ ids → ⎋ JSON
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/skibine/vm-pulse/internal/logging"
)

// aiModelsHTTP is the client used for upstream /models calls; package-level so tests can shrink
// the timeout or replace transport behaviour if needed.
var aiModelsHTTP = &http.Client{Timeout: 15 * time.Second}

// region STRUCT_localLLMTarget [DOMAIN(9): AI; CONCEPT(6): LocalDetect; TECH(5): struct]
// @purpose One localhost LLM server to probe for the "detect local" feature.
// endregion STRUCT_localLLMTarget
type localLLMTarget struct {
	ID      string // preset id (matches web/src/lib/providers.js)
	Label   string
	BaseURL string // e.g. http://127.0.0.1:11434/v1
}

// localLLMTargets is the probed set; package-level so tests can repoint it at httptest servers.
var localLLMTargets = []localLLMTarget{
	{ID: "ollama", Label: "Ollama", BaseURL: "http://127.0.0.1:11434/v1"},
	{ID: "lmstudio", Label: "LM Studio", BaseURL: "http://127.0.0.1:1234/v1"},
	{ID: "vllm", Label: "vLLM", BaseURL: "http://127.0.0.1:8000/v1"},
}

// region FUNC_aiModels [DOMAIN(9): AI; CONCEPT(7): ModelList; TECH(8): net/http]
// @purpose Proxy the configured provider's GET /models so Settings can offer a model dropdown.
//
//	OpenAI / OpenRouter / Ollama / LM Studio / vLLM all expose {data:[{id}]} here. Uses the
//	STORED api_url + api_key; the key never round-trips through the browser.
//
// @io () -> {models:[id]}
// @complexity 4
// @invariants
//   - Returns 400 (not 502) when no api_url is configured yet — distinct from a bad provider.
//
// endregion FUNC_aiModels
func (a *crudAPI) aiModels(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.st.GetAIConfig(r.Context())
	if err != nil {
		a.writeErr(w, "aiModels", err)
		return
	}
	if strings.TrimSpace(cfg.APIURL) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no api_url configured — save your provider first"})
		return
	}
	ids, err := fetchModelIDs(r.Context(), cfg.APIURL, cfg.APIKey)
	if err != nil {
		logging.LDD(a.logger, 9, "aiModels", "FETCH_FAIL", hostOf(cfg.APIURL)+": "+err.Error())
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "provider unreachable: " + err.Error()})
		return
	}
	logging.LDD(a.logger, 7, "aiModels", "LIST", fmt.Sprintf("host=%s count=%d", hostOf(cfg.APIURL), len(ids)))
	writeJSON(w, http.StatusOK, map[string]any{"models": ids})
}

// region FUNC_probeLocalAI [DOMAIN(9): AI; CONCEPT(7): LocalDetect; TECH(8): net/http]
// @purpose Detect which local LLM servers run on the VMPulse host (loopback only) so the user
//
//	can pick Ollama / LM Studio / vLLM without typing a URL. Probes run in parallel with a
//	short per-target timeout; a server is "alive" iff its /models responds 2xx + parseable ids.
//
// @io () -> {targets:[{id,label,alive,models}]}
// @complexity 5
// endregion FUNC_probeLocalAI
func (a *crudAPI) probeLocalAI(w http.ResponseWriter, r *http.Request) {
	targets := localLLMTargets
	results := make([]map[string]any, len(targets))
	var wg sync.WaitGroup
	for i, t := range targets {
		wg.Add(1)
		go func(i int, t localLLMTarget) {
			defer wg.Done()
			alive := true
			// BUG_FIX_CONTEXT: local servers ignore the Authorization header, but Ollama rejects an
			// empty bearer in some builds — sending "local" is universally tolerated and never sent
			// off-box (loopback only), so it is harmless here.
			models, err := fetchModelIDs(r.Context(), t.BaseURL, "local")
			if err != nil {
				alive = false
				models = nil
			}
			results[i] = map[string]any{"id": t.ID, "label": t.Label, "alive": alive, "models": models}
		}(i, t)
	}
	wg.Wait()
	logging.LDD(a.logger, 8, "probeLocalAI", "PROBED", fmt.Sprintf("alive=%d/%d", countAlive(results), len(results)))
	writeJSON(w, http.StatusOK, map[string]any{"targets": results})
}

// fetchModelIDs GETs {base}/models (OpenAI-compatible) and extracts data[].id tolerantly.
// A missing/non-2xx response is an error; an empty-but-valid list is a success with zero ids.
func fetchModelIDs(ctx context.Context, baseURL, apiKey string) ([]string, error) {
	endpoint := strings.TrimRight(baseURL, "/") + "/models"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(apiKey) != "" {
		httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	}
	resp, err := aiModelsHTTP.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var parsed struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	out := make([]string, 0, len(parsed.Data))
	for _, m := range parsed.Data {
		if m.ID != "" {
			out = append(out, m.ID)
		}
	}
	return out, nil
}

// hostOf returns the host[:port] of a URL, falling back to the raw string on parse failure.
func hostOf(raw string) string {
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return raw
}

// countAlive tallies targets flagged alive (used only for an LDD summary line).
func countAlive(results []map[string]any) int {
	n := 0
	for _, r := range results {
		if r == nil {
			continue
		}
		if v, _ := r["alive"].(bool); v {
			n++
		}
	}
	return n
}
