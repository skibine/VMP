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
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/skibine/vm-pulse/internal/auth"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/ssh"
	"github.com/skibine/vm-pulse/internal/store"
)

// registerSettings wires settings routes.
func registerSettings(mux *http.ServeMux, a *crudAPI) {
	mux.HandleFunc("GET /api/settings/ai", a.getAISettings)
	mux.HandleFunc("PUT /api/settings/ai", a.updateAISettings)
	mux.HandleFunc("GET /api/settings/locale", a.getLocale)
	mux.HandleFunc("PUT /api/settings/locale", a.setLocale)

	// AI model discovery: provider /models proxy + localhost LLM detection.
	mux.HandleFunc("GET /api/ai/models", a.aiModels)
	mux.HandleFunc("GET /api/ai/probe-local", a.probeLocalAI)

	mux.HandleFunc("GET /api/vms/{id}/credentials", a.getVMCreds)
	mux.HandleFunc("GET /api/vms/{id}/inventory", a.vmInventory)
	mux.HandleFunc("POST /api/vms/{id}/inventory/refresh", a.refreshInventory)
	mux.HandleFunc("PUT /api/vms/{id}/credentials", a.setVMCreds)
	mux.HandleFunc("DELETE /api/vms/{id}/credentials", a.deleteVMCreds)
	mux.HandleFunc("PUT /api/vms/{id}/ai-access", a.setAIAccess)
}

// ── AI settings ─────────────────────────────────────────────────────────────────────

// getLocale returns the operator's UI locale (drives alert-message language).
func (a *crudAPI) getLocale(w http.ResponseWriter, r *http.Request) {
	loc, _ := a.st.GetSetting(r.Context(), "ui_locale")
	if loc == "" {
		loc = "en"
	}
	writeJSON(w, http.StatusOK, map[string]string{"locale": loc})
}

// setLocale stores the operator's UI locale so server-side alerts are sent in that language.
func (a *crudAPI) setLocale(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Locale string `json:"locale"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if body.Locale != "ru" && body.Locale != "en" {
		body.Locale = "en"
	}
	if err := a.st.SetSetting(r.Context(), "ui_locale", body.Locale, false); err != nil {
		a.writeErr(w, "setLocale", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"locale": body.Locale})
}

func (a *crudAPI) getAISettings(w http.ResponseWriter, r *http.Request) {	cfg, err := a.st.GetAIConfig(r.Context())
	if err != nil {
		a.writeErr(w, "getAISettings", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"api_url":      cfg.APIURL,
		"model":        cfg.Model,
		"has_key":      cfg.APIKey != "",
		"auto_approve": a.st.IsAIAutoApprove(r.Context()),
	})
}

func (a *crudAPI) updateAISettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		APIURL      string `json:"api_url"`
		APIKey      string `json:"api_key"`
		Model       string `json:"model"`
		AutoApprove *bool  `json:"auto_approve"` // pointer so false is distinguishable from omitted
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
	if body.AutoApprove != nil {
		val := "false"
		if *body.AutoApprove {
			val = "true"
		}
		_ = a.st.SetSetting(r.Context(), store.SettingAIAutoApprove, val, false)
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
	resp := map[string]any{"has_secret": false, "has_sudo": false, "ssh_user": "", "auth_type": ""}
	if has {
		resp["has_secret"] = creds.Secret != ""
		resp["has_sudo"] = creds.SudoPassword != ""
		resp["ssh_user"] = creds.SSHUser
		resp["auth_type"] = creds.AuthType
		// Surface the persisted inventory so the "system // profile" block survives navigation.
		// Strip the heavy packages_list here (it can be hundreds of names) — fetched lazily on
		// expand via GET /api/vms/{id}/inventory so the hot detail-load stays light.
		if creds.Inventory != "" {
			var inv map[string]any
			if err := json.Unmarshal([]byte(creds.Inventory), &inv); err == nil {
				delete(inv, "packages_list")
				resp["inventory"] = inv
			}
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// refreshInventory re-runs the SSH inventory probe and persists it (manual refresh of the
// "system // profile" block). Plane B: needs SSH credentials.
func (a *crudAPI) refreshInventory(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	client, _, derr := a.dialer.Dial(r.Context(), id)
	if derr != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": classifyDialKind(derr), "detail": derr.Error()})
		return
	}
	defer client.Close()
	inv, err := a.dialer.Inventory(r.Context(), client)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]any{"error": "other", "detail": err.Error()})
		return
	}
	if blob, err := json.Marshal(inv); err == nil {
		_ = a.st.SetVMInventory(r.Context(), id, string(blob))
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "inventory": inv})
}

// vmInventory returns the FULL persisted SSH inventory (incl. packages_list) for the lazy-loaded
// "packages" details block. Plane-B read of stored inventory (no SSH round-trip).
func (a *crudAPI) vmInventory(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	creds, has, err := a.st.GetVMCredentials(r.Context(), id)
	if err != nil {
		a.writeErr(w, "vmInventory", err)
		return
	}
	if !has || creds.Inventory == "" {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	var inv any
	if err := json.Unmarshal([]byte(creds.Inventory), &inv); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{})
		return
	}
	writeJSON(w, http.StatusOK, inv)
}

func (a *crudAPI) setVMCreds(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	// Cred-gate (symmetric to the one on 2FA-disable): storing SSH credentials requires 2FA on.
	// The vault holds privileged secrets — they must never sit behind a single-factor login.
	if uid, ok := auth.FromContext(r.Context()); ok {
		if u, err := a.st.GetUser(r.Context(), uid); err != nil || !u.TOTPEnabled {
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error": "enable 2FA before storing SSH credentials — open Settings → 2FA",
			})
			return
		}
	}
	var body struct {
		SSHUser       string `json:"ssh_user"`
		AuthType      string `json:"auth_type"`
		Secret        string `json:"secret"`
		KeyPassphrase string `json:"key_passphrase"`
		SudoPassword  string `json:"sudo_password"`
	}
	if !readJSON(w, r, &body) {
		return
	}

	// Preserve the existing secret/passphrase/sudo when the request omits them (so the user can
	// change only the ssh_user/auth_type without re-pasting the key every time). Sudo password is
	// preserved unless the operator explicitly clears it via a dedicated clear endpoint/flag.
	cur, has, _ := a.st.GetVMCredentials(r.Context(), id)
	secret := body.Secret
	if secret == "" && has {
		secret = cur.Secret
	}
	pass := body.KeyPassphrase
	if pass == "" && has && body.Secret == "" {
		pass = cur.KeyPassphrase
	}
	sudo := body.SudoPassword
	if sudo == "" && has {
		sudo = cur.SudoPassword // sudo is orthogonal to the SSH key: preserve unless explicitly changed
	}
	if err := a.st.SetVMCredentials(r.Context(), store.VMCredentials{
		VMID: id, SSHUser: body.SSHUser, AuthType: body.AuthType, Secret: secret,
		KeyPassphrase: pass, SudoPassword: sudo,
	}); err != nil {
		a.writeErr(w, "setVMCreds", err)
		return
	}

	// Validate immediately: dial with the just-stored creds and, on success, collect a VPS profile.
	resp := map[string]any{"ok": true, "validated": false}
	if secret == "" && body.AuthType != "agent" {
		resp["error_kind"] = "no_credentials"
		writeJSON(w, http.StatusOK, resp)
		return
	}
	client, _, derr := a.dialer.Dial(r.Context(), id)
	if derr != nil {
		resp["error_kind"] = classifyDialKind(derr)
		resp["error_detail"] = derr.Error()
		logging.LDD(a.logger, 9, "setVMCreds", "VALIDATE_FAIL", derr.Error())
		writeJSON(w, http.StatusOK, resp)
		return
	}
	defer client.Close()
	resp["validated"] = true
	if inv, err := a.dialer.Inventory(r.Context(), client); err == nil {
		resp["inventory"] = inv
		// Persist the profile so it survives VM navigation (was ephemeral before).
		if blob, err := json.Marshal(inv); err == nil {
			_ = a.st.SetVMInventory(r.Context(), id, string(blob))
		}
	}
	logging.LDD(a.logger, 8, "setVMCreds", "VALIDATED", "")
	writeJSON(w, http.StatusOK, resp)
}

// setAIAccess grants or revokes the AI assistant's access to a single VM (opt-in per VM).
func (a *crudAPI) setAIAccess(w http.ResponseWriter, r *http.Request) {
	id, ok := parseID(w, r)
	if !ok {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if err := a.st.SetAIEnabled(r.Context(), id, body.Enabled); err != nil {
		a.writeErr(w, "setAIAccess", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ai_enabled": body.Enabled})
}

// classifyDialKind maps a dialer error to a machine-readable kind for the UI.
func classifyDialKind(err error) string {
	switch {
	case errors.Is(err, ssh.ErrNoCredentials):
		return "no_credentials"
	case errors.Is(err, ssh.ErrHostKeyChanged):
		return "host_key_changed"
	}
	msg := err.Error()
	if strings.Contains(msg, "unable to authenticate") || strings.Contains(msg, "handshake") {
		return "auth_failed"
	}
	if strings.Contains(msg, "connection refused") || strings.Contains(msg, "i/o timeout") ||
		strings.Contains(msg, "no route to host") || strings.Contains(msg, "timeout") {
		return "unreachable"
	}
	return "ssh_dial_failed"
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
