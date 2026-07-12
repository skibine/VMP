// Package api — settings endpoints (AI provider + VM credentials).
//
// region MODULE_CONTRACT [DOMAIN(9): API; CONCEPT(8): Settings; TECH(8): net/http]
// @purpose Manage in-app settings. Secrets (AI key, VM secret) are written vault-encrypted and
//
//	NEVER returned by GET (only has_key / has_secret flags).
//
// @invariants
//   - GET responses contain no plaintext secrets.
//   - PUT /api/settings/ai with an empty api_key keeps the existing key.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: settings, AI config, api_key, masked, VM credentials, ssh_user, has_secret
// STRUCTURE: ▶ ┌{ai/creds}┐ → ○ store.Set → ⎋ ; GET → 〈mask secret〉 → ⊕ JSON
package api

import (
	"net/http"

	"github.com/skibine/vm-pulse/internal/store"
)

// registerSettings wires settings routes.
func registerSettings(mux *http.ServeMux, a *crudAPI) {
	mux.HandleFunc("GET /api/settings/ai", a.getAISettings)
	mux.HandleFunc("PUT /api/settings/ai", a.updateAISettings)

	mux.HandleFunc("GET /api/vms/{id}/credentials", a.getVMCreds)
	mux.HandleFunc("PUT /api/vms/{id}/credentials", a.setVMCreds)
	mux.HandleFunc("DELETE /api/vms/{id}/credentials", a.deleteVMCreds)
}

// ── AI settings ─────────────────────────────────────────────────────────────────────

func (a *crudAPI) getAISettings(w http.ResponseWriter, r *http.Request) {
	cfg, err := a.st.GetAIConfig(r.Context())
	if err != nil {
		a.writeErr(w, "getAISettings", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"api_url": cfg.APIURL,
		"model":   cfg.Model,
		"has_key": cfg.APIKey != "",
	})
}

func (a *crudAPI) updateAISettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		APIURL string `json:"api_url"`
		APIKey string `json:"api_key"`
		Model  string `json:"model"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	// Read current to preserve the key when the request omits it.
	cur, _ := a.st.GetAIConfig(r.Context())
	key := body.APIKey
	if key == "" {
		key = cur.APIKey
	}
	if err := a.st.SetAIConfig(r.Context(), store.AIConfig{APIURL: body.APIURL, APIKey: key, Model: body.Model}); err != nil {
		a.writeErr(w, "updateAISettings", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// ── VM credentials ──────────────────────────────────────────────────────────────────

func (a *crudAPI) getVMCreds(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	creds, has, err := a.st.GetVMCredentials(r.Context(), id)
	if err != nil {
		a.writeErr(w, "getVMCreds", err)
		return
	}
	resp := map[string]any{"has_secret": false, "ssh_user": "", "auth_type": ""}
	if has {
		resp["has_secret"] = creds.Secret != ""
		resp["ssh_user"] = creds.SSHUser
		resp["auth_type"] = creds.AuthType
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *crudAPI) setVMCreds(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var body struct {
		SSHUser  string `json:"ssh_user"`
		AuthType string `json:"auth_type"`
		Secret   string `json:"secret"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := a.st.SetVMCredentials(r.Context(), store.VMCredentials{
		VMID: id, SSHUser: body.SSHUser, AuthType: body.AuthType, Secret: body.Secret,
	}); err != nil {
		a.writeErr(w, "setVMCreds", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *crudAPI) deleteVMCreds(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	if err := a.st.DeleteVMCredentials(r.Context(), id); err != nil {
		a.writeErr(w, "deleteVMCreds", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
