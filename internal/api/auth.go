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
	"net/http"
	"strings"

	"github.com/skibine/vm-pulse/internal/audit"
	"github.com/skibine/vm-pulse/internal/auth"
	"github.com/skibine/vm-pulse/internal/logging"
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
	_ = s.store.SetLastLogin(r.Context(), user.ID)
	_ = audit.Append(s.store.DB, s.logger, audit.Entry{
		Plane: audit.PlaneB, UserID: user.ID, Action: "auth.login", Detail: `{"ok":true}`, Success: true,
	})
	logging.LDD(s.logger, 9, "login", "OK", "username="+body.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"token": token, "username": user.Username, "role": user.Role,
	})
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
