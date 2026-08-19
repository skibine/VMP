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
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/skibine/vm-pulse/internal/audit"
	"github.com/skibine/vm-pulse/internal/auth"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
	qrcode "github.com/skip2/go-qrcode"
)

// clientIP strips the port from RemoteAddr for rate-limit keys. X-Forwarded-For is
// deliberately NOT honored: trusting it lets anyone behind no proxy (or a lying proxy)
// rotate the limiter key and bypass the cap.
func clientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}

// Login brute-force window: 10 attempts per IP+username per 15 minutes. Successful login
// clears the key, so an operator's typo streak never locks them out.
const (
	loginMaxAttempts = 10
	loginWindow      = 15 * time.Minute
)

// dummyHash burns one argon2 verification when the username does not exist, so a missing-user
// attempt costs the same CPU time as an existing one (timing-enumeration damper).
var dummyHash, _ = auth.HashPassword("vmpulse-dummy-verify-target")

// region FUNC_login [DOMAIN(9): API; CONCEPT(7): Login; TECH(7): net/http]
// @purpose Verify credentials and issue a session token. Rate-limited per IP+username;
//
//	nonexistent users burn a dummy argon2 verify (anti-enumeration).
//
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

	lkey := clientIP(r) + "|" + body.Username
	if !s.loginLimiter.Allow(lkey) {
		logging.LDD(s.logger, 9, "login", "RATE_LIMITED", "ip="+clientIP(r)+" username="+body.Username)
		w.Header().Set("Retry-After", "300")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try later"})
		return
	}

	user, err := s.store.GetUserByUsername(r.Context(), body.Username)
	if err != nil {
		// Anti-enumeration: pay the same argon2 cost as for an existing user, then deny.
		auth.VerifyPassword(body.Password, dummyHash)
	}
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
	s.loginLimiter.Clear(lkey)
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
	// Same brute-force damper as step 1: a leaked pending token must not allow unlimited code
	// guessing (10^6 codes, but skew gives ~3 live candidates at a time).
	lkey := clientIP(r) + "|2fa|" + strings.TrimSpace(body.PendingToken)
	if !s.loginLimiter.Allow(lkey) {
		w.Header().Set("Retry-After", "300")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try later"})
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
	// TOTP with REPLAY PROTECTION: the matched counter step must be strictly greater than the
	// last consumed one - a captured code is useless within its ~60-90s validity window.
	// (Backup codes remain one-time by consumption, no step semantics.)
	step, valid := auth.ValidateStep(user.TOTPSecret, code, time.Now())
	if valid && step <= user.TOTPLastStep {
		valid = false // replay of the already-consumed step
		logging.LDD(s.logger, 9, "loginTwoFA", "REPLAY_REFUSED", "step replayed")
	}
	if !valid {
		if !s.tryBackupCode(r.Context(), user, code) {
			_ = audit.Append(s.store.DB, s.logger, audit.Entry{
				Plane: audit.PlaneB, UserID: user.ID, Action: "auth.login_2fa", Success: false,
				Detail: "bad code",
			})
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid code"})
			return
		}
	} else {
		// Persist the consumed TOTP step (replay guard for the ~60-90s validity window).
		_ = s.store.SetTOTPLastStep(r.Context(), user.ID, step)
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
	// Whether any VM stores SSH credentials — surfaced so the UI can explain WHY 2FA cannot be
	// turned off (the cred-gate: disable is refused while privileged secrets remain in the vault).
	// Include the names of the cred-carrying servers so the operator knows exactly what to clear.
	type vmRef struct {
		ID   int64  `json:"id"`
		Name string `json:"name"`
	}
	var credVMs []vmRef
	if withCreds, err := s.store.VMsWithCreds(r.Context()); err == nil && len(withCreds) > 0 {
		all, _ := s.store.ListVMs(r.Context(), true)
		for _, v := range all {
			if withCreds[v.ID] {
				credVMs = append(credVMs, vmRef{ID: v.ID, Name: v.Name})
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"enabled": u.TOTPEnabled, "has_vm_credentials": len(credVMs) > 0, "cred_vms": credVMs})
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
	// Session revocation: every existing session (incl. possibly stolen ones) dies with the
	// old credential. The CURRENT caller must re-login - the SPA token store will 401.
	if err := s.store.DeleteSessionsForUser(r.Context(), uid); err != nil {
		logging.LDD(s.logger, 9, "changePassword", "REVOKE_FAIL", err.Error())
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
