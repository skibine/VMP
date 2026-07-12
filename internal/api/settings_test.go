// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: SettingsAPI; TECH(8]: go test,httptest]
// @purpose Verify AI settings GET (masked key, never returns secret) + PUT (empty key preserves),
//
//	and VM credentials GET/PUT/DELETE (secret never in response).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, settings, AI, masked, VM credentials, secret, http
package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

func TestHTTP_SettingsAI_MaskedAndPreserve(t *testing.T) {
	srv, buf := newServer(t)

	// Initial: no api_key field in response.
	rec := do(srv, http.MethodGet, "/api/settings/ai", "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "api_key") {
		t.Fatalf("initial GET want 200 + no api_key field, got: %s", rec.Body.String())
	}

	// PUT with a key.
	rec = do(srv, http.MethodPut, "/api/settings/ai", `{"api_url":"https://api","api_key":"sk-secret","model":"gpt"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT want 200, got %d", rec.Code)
	}
	// GET has_key true, body must NOT contain the secret value.
	rec = do(srv, http.MethodGet, "/api/settings/ai", "")
	if !strings.Contains(rec.Body.String(), `"has_key":true`) {
		t.Fatalf("has_key want true: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "sk-secret") {
		t.Fatalf("api_key leaked into GET: %s", rec.Body.String())
	}

	// PUT with empty key must preserve the stored key (url/model updated).
	rec = do(srv, http.MethodPut, "/api/settings/ai", `{"api_url":"https://api2","api_key":"","model":"gpt2"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT(empty key) want 200, got %d", rec.Code)
	}
	cfg, _ := srv.store.GetAIConfig(context.Background())
	if cfg.APIKey != "sk-secret" {
		t.Fatalf("empty-key PUT must preserve key, got %q", cfg.APIKey)
	}
	if cfg.APIURL != "https://api2" || cfg.Model != "gpt2" {
		t.Fatalf("url/model not updated: %+v", cfg)
	}

	printIMPFromBuf(t, buf)
}

func TestHTTP_VMCreds_SecretNotLeaked(t *testing.T) {
	srv, _ := newServer(t)
	// Create a VM.
	rec := do(srv, http.MethodPost, "/api/vms", `{"name":"v","hostname":"h","port_ssh":22}`)
	var vm struct {
		ID int64 `json:"id"`
	}
	decode(t, rec, &vm)
	id := strconv.FormatInt(vm.ID, 10)

	// Initial GET: has_secret false.
	rec = do(srv, http.MethodGet, "/api/vms/"+id+"/credentials", "")
	if !strings.Contains(rec.Body.String(), `"has_secret":false`) {
		t.Fatalf("initial creds want has_secret false: %s", rec.Body.String())
	}

	// PUT creds.
	rec = do(srv, http.MethodPut, "/api/vms/"+id+"/credentials",
		`{"ssh_user":"root","auth_type":"password","secret":"topsecret"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT creds want 200, got %d", rec.Code)
	}

	// GET: has_secret true, secret value NOT present.
	rec = do(srv, http.MethodGet, "/api/vms/"+id+"/credentials", "")
	if !strings.Contains(rec.Body.String(), `"has_secret":true`) {
		t.Fatalf("creds want has_secret true: %s", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "topsecret") {
		t.Fatalf("vm secret leaked into GET: %s", rec.Body.String())
	}

	// DELETE.
	rec = do(srv, http.MethodDelete, "/api/vms/"+id+"/credentials", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("DELETE creds want 200, got %d", rec.Code)
	}
	rec = do(srv, http.MethodGet, "/api/vms/"+id+"/credentials", "")
	if !strings.Contains(rec.Body.String(), `"has_secret":false`) {
		t.Fatalf("after delete want has_secret false: %s", rec.Body.String())
	}
}
