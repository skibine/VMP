// Package api — auth endpoints (login/logout/me). Plane B access control.
//
// region MODULE_CONTRACT [DOMAIN(9): API; CONCEPT(8): AuthN; TECH(8): net/http]
// @purpose Issue and revoke session tokens and report the current user. login is public; the
//
//	middleware gates logout/me (and everything else under /api/).
//
// @invariants
//   - login failure is recorded in the tamper-evident audit chain (success=false).
//   - Tokens are returned in JSON; clients send them as Bearer or cookie.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: auth, login, logout, me, session, token, 401, audit
// STRUCTURE: ▶ ┌{username,password}┐ → ○ verify → ⊕ CreateSession → ⎋ {token} ; logout → DELETE
package api

import (
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/skibine/vm-pulse/internal/audit"
	"github.com/skibine/vm-pulse/internal/auth"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
	qrcode "github.com/skip2/go-qrcode"
)

// region FUNC_login [DOMAIN(9): API; CONCEPT(7): Login; TECH(7): net/http]
// @purpose Verify credentials and issue a session token.
// @complexity 5
// endregion FUNC_login
func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	body.Username = strings.TrimSpace(body.Username)

	user, err := s.store.GetUserByUsername(r.Context(), body.Username)
	if err != nil || !user.IsActive || !auth.VerifyPassword(body.Password, user.PasswordHash) {
		_ = audit.Append(s.store.DB, s.logger, audit.Entry{
			Plane: audit.PlaneB, Action: "auth.login", Detail: `{"username":"` + body.Username + `","ok":false}`,
			Success: false,
		})
		logging.LDD(s.logger, 9, "login", "DENY", "username="+body.Username)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	// First factor verified. If 2FA is enabled, issue a short-lived pending token for step 2.
	if user.TOTPEnabled {
		pending, err := s.pending2FA.Issue(user.ID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "pending token"})
			return
		}
		logging.LDD(s.logger, 8, "login", "TWOFA_PENDING", "username="+body.Username)
		writeJSON(w, http.StatusOK, map[string]any{"requires_2fa": true, "pending_token": pending})
		return
	}
	token, err := auth.NewToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token"})
		return
	}
	if err := s.store.CreateSession(r.Context(), token, user.ID, auth.SessionTTL); err != nil {
		aerr := err
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session: " + aerr.Error()})
		return
	}
	s.finishLogin(w, r, user, token)
}

// finishLogin stamps last-login, writes the audit entry and the JSON session response.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, user store.User, token string) {
	_ = s.store.SetLastLogin(r.Context(), user.ID)
	_ = audit.Append(s.store.DB, s.logger, audit.Entry{
		Plane: audit.PlaneB, UserID: user.ID, Action: "auth.login", Detail: `{"ok":true}`, Success: true,
	})
	logging.LDD(s.logger, 9, "login", "OK", "username="+user.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token, "username": user.Username, "role": user.Role,
	})
}

// loginTwoFA completes a two-step login: redeem the pending token with a TOTP code (or backup code).
func (s *Server) loginTwoFA(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PendingToken string `json:"pending_token"`
		Code         string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	uid, ok := s.pending2FA.Consume(strings.TrimSpace(body.PendingToken))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "pending token expired or invalid"})
		return
	}
	user, err := s.store.GetUser(r.Context(), uid)
	if err != nil || !user.TOTPEnabled {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "2fa not enabled"})
		return
	}
	code := strings.TrimSpace(body.Code)
	// Try a TOTP code first; fall back to a one-time backup code.
	if !auth.Validate(user.TOTPSecret, code, time.Now()) {
		if !s.tryBackupCode(r.Context(), user, code) {
			_ = audit.Append(s.store.DB, s.logger, audit.Entry{
				Plane: audit.PlaneB, UserID: user.ID, Action: "auth.login_2fa", Success: false,
				Detail: "bad code",
			})
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
			return
		}
	}
	token, err := auth.NewToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "token"})
		return
	}
	if err := s.store.CreateSession(r.Context(), token, user.ID, auth.SessionTTL); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "session"})
		return
	}
	s.finishLogin(w, r, user, token)
}

// tryBackupCode checks the code against stored one-time backup hashes; consumes a match.
func (s *Server) tryBackupCode(ctx context.Context, user store.User, code string) bool {
	var hashes []string
	if user.BackupCodes == "" || json.Unmarshal([]byte(user.BackupCodes), &hashes) != nil {
		return false
	}
	for i, h := range hashes {
		if auth.VerifyPassword(code, h) {
			_ = s.store.ConsumeBackupCode(ctx, user.ID, hashes, i)
			return true
		}
	}
	return false
}

// region FUNC_twoFAStatus [DOMAIN(9): Security; CONCEPT(7): 2FA; TECH(5): net/http]
// @purpose Report whether the current user has 2FA enabled.
// @complexity 2
// endregion FUNC_twoFAStatus
func (s *Server) twoFAStatus(w http.ResponseWriter, r *http.Request) {
	uid, ok := auth.FromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	u, err := s.store.GetUser(r.Context(), uid)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": u.TOTPEnabled})
}

// region FUNC_twoFASetup [DOMAIN(9): Security; CONCEPT(7): 2FA; TECH(7): net/http,totp]
// @purpose Generate (or reuse) a TOTP secret + QR for the current user. Does NOT enable yet.
// @complexity 5
// endregion FUNC_twoFASetup
func (s *Server) twoFASetup(w http.ResponseWriter, r *http.Request) {
	uid, ok := auth.FromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	u, err := s.store.GetUser(r.Context(), uid)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	secret := u.TOTPSecret
	if !u.TOTPEnabled && secret == "" {
		secret, err = auth.GenerateSecret()
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "secret"})
			return
		}
	}
	uri := auth.OTPAuthURI(u.Username, secret, "VMPulse")
	png, err := qrcode.Encode(uri, qrcode.Medium, 220)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "qr"})
		return
	}
	if !u.TOTPEnabled {
		http.SetCookie(w, &http.Cookie{
			Name: "vmp_2fa_pending", Value: secret, Path: "/", HttpOnly: true,
			MaxAge: 300, SameSite: http.SameSiteLaxMode,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":      secret,
		"otpauth_uri": uri,
		"qr_data_url": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png),
		"already_on":  u.TOTPEnabled,
	})
}

// region FUNC_twoFAEnable [DOMAIN(9): Security; CONCEPT(7): 2FA; TECH(6): net/http]
// @purpose Confirm a TOTP code against the pending secret and enable 2FA. Returns backup codes once.
// @complexity 5
// endregion FUNC_twoFAEnable
func (s *Server) twoFAEnable(w http.ResponseWriter, r *http.Request) {
	uid, ok := auth.FromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var body struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	secret := strings.TrimSpace(r.URL.Query().Get("secret"))
	if secret == "" {
		if c, err := r.Cookie("vmp_2fa_pending"); err == nil {
			secret = c.Value
		}
	}
	if secret == "" || !auth.Validate(secret, strings.TrimSpace(body.Code), time.Now()) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid code"})
		return
	}
	codes, hashes, err := generateBackupCodes(8)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "backup codes"})
		return
	}
	blob, _ := json.Marshal(hashes)
	if err := s.store.EnableTOTP(r.Context(), uid, secret, string(blob)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "vmp_2fa_pending", Value: "", Path: "/", MaxAge: -1})
	_ = audit.Append(s.store.DB, s.logger, audit.Entry{
		Plane: audit.PlaneB, UserID: uid, Action: "auth.2fa_enable", Success: true,
	})
	logging.LDD(s.logger, 9, "2fa", "ENABLED", fmt.Sprintf("uid=%d", uid))
	writeJSON(w, http.StatusOK, map[string]any{"enabled": true, "backup_codes": codes})
}

// region FUNC_twoFADisable [DOMAIN(9): Security; CONCEPT(7): 2FA; TECH(6): net/http]
// @purpose Disable 2FA after password re-entry. Refused while any VM stores SSH credentials (cred-gate).
// @complexity 5
// endregion FUNC_twoFADisable
func (s *Server) twoFADisable(w http.ResponseWriter, r *http.Request) {
	uid, ok := auth.FromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u, err := s.store.GetUser(r.Context(), uid)
	if err != nil || !auth.VerifyPassword(body.Password, u.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid password"})
		return
	}
	// Cred-gate: cannot disable 2FA while privileged VM credentials exist.
	if has, _ := s.store.HasAnyVMCredentials(r.Context()); has {
		writeJSON(w, http.StatusConflict, map[string]string{
			"error": "cannot disable 2FA while VMs store SSH credentials — remove them first",
		})
		return
	}
	if err := s.store.DisableTOTP(r.Context(), uid); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_ = audit.Append(s.store.DB, s.logger, audit.Entry{
		Plane: audit.PlaneB, UserID: uid, Action: "auth.2fa_disable", Success: true,
	})
	logging.LDD(s.logger, 9, "2fa", "DISABLED", fmt.Sprintf("uid=%d", uid))
	writeJSON(w, http.StatusOK, map[string]bool{"disabled": true})
}

// changePassword lets an authenticated user rotate their own password. Requires the current
// password (re-auth) so a hijacked session cookie alone cannot change it.
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	uid, ok := auth.FromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var body struct {
		Current string `json:"current_password"`
		Next    string `json:"new_password"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	u, err := s.store.GetUser(r.Context(), uid)
	if err != nil || !auth.VerifyPassword(body.Current, u.PasswordHash) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
		return
	}
	if len(body.Next) < 8 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "new password must be at least 8 characters"})
		return
	}
	hash, err := auth.HashPassword(body.Next)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "hash failed"})
		return
	}
	if err := s.store.SetPassword(r.Context(), uid, hash); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	_ = audit.Append(s.store.DB, s.logger, audit.Entry{
		Plane: audit.PlaneB, UserID: uid, Action: "auth.password_change", Success: true,
	})
	logging.LDD(s.logger, 9, "auth", "PASSWORD_CHANGED", fmt.Sprintf("uid=%d", uid))
	writeJSON(w, http.StatusOK, map[string]bool{"changed": true})
}

// generateBackupCodes returns N plaintext one-time codes and their argon2id hashes.
func generateBackupCodes(n int) ([]string, []string, error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	codes := make([]string, 0, n)
	hashes := make([]string, 0, n)
	for i := 0; i < n; i++ {
		buf := make([]byte, 8)
		if _, err := rand.Read(buf); err != nil {
			return nil, nil, err
		}
		code := "vmp-" + enc.EncodeToString(buf)
		h, err := auth.HashPassword(code)
		if err != nil {
			return nil, nil, err
		}
		codes = append(codes, code)
		hashes = append(hashes, h)
	}
	return codes, hashes, nil
}

// region FUNC_logout [DOMAIN(9): API; CONCEPT(6): Logout; TECH(6): net/http]
// @purpose Revoke the current session token.
// @complexity 3
// endregion FUNC_logout
func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	token := extractTokenRaw(r)
	if token != "" {
		_ = s.store.DeleteSession(r.Context(), token)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// region FUNC_me [DOMAIN(9): API; CONCEPT(6): CurrentUser; TECH(5): net/http]
// @purpose Return the authenticated user's profile.
// @complexity 3
// endregion FUNC_me
func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	uid, ok := auth.FromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	u, err := s.store.GetUser(r.Context(), uid)
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"id": u.ID, "username": u.Username, "role": u.Role, "is_active": u.IsActive,
	})
}

// extractTokenRaw mirrors auth.extractToken without importing its unexported helper.
func extractTokenRaw(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	if c, err := r.Cookie("vmpulse_session"); err == nil {
		return c.Value
	}
	return ""
}
