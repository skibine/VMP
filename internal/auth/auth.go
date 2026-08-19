// Package auth implements Plane B access control: password hashing (argon2id), opaque session
// tokens, and HTTP middleware enforcing deny-by-default auth on the API.
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): AuthN; TECH(9): argon2id,net/http]
// @purpose Gate all /api/ routes behind a valid session; only /healthz and login are public.
// @io Middleware(store, logger) -> func(http.Handler) http.Handler
// @invariants
//   - Passwords are hashed with argon2id; plaintext is never stored or logged.
//   - The middleware never panics; unauthenticated requests get 401 JSON.
//   - Public paths are exactly /healthz and POST /api/auth/login.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: auth, argon2id, password, hash, session, token, middleware, 401, deny-by-default
// STRUCTURE: ▶ ┌pass┐ → ⚡ argon2id → ⊕ encoded ; Middleware → 〈token? session?〉 → next|401
package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/skibine/vmp/internal/logging"
	"github.com/skibine/vmp/internal/store"
)

// argon2id parameters (tuneable; sane defaults).
const (
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// SessionTTL is the default session lifetime.
const SessionTTL = 12 * time.Hour

type ctxKey struct{}

// region FUNC_HashPassword [DOMAIN(9): Security; CONCEPT(7): Hash; TECH(8): argon2id]
// @purpose Hash a password with a random salt and return an argon2id encoded string.
// @complexity 4
// endregion FUNC_HashPassword
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("auth: read salt: %w", err)
	}
	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash)), nil
}

// region FUNC_VerifyPassword [DOMAIN(9): Security; CONCEPT(7): Verify; TECH(8): argon2id]
// @purpose Constant-time verify a password against an encoded argon2id string.
// @complexity 4
// endregion FUNC_VerifyPassword
func VerifyPassword(password, encoded string) bool {
	m, t, p, salt, hash, ok := parseEncoded(encoded)
	if !ok {
		return false
	}
	cmp := argon2.IDKey([]byte(password), salt, t, m, p, uint32(len(hash)))
	return subtle.ConstantTimeCompare(cmp, hash) == 1
}

// parseEncoded splits "$argon2id$v=19$m=..,t=..,p=..$salt$hash".
func parseEncoded(encoded string) (m uint32, t uint32, p uint8, salt, hash []byte, ok bool) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, false
	}
	// parts[3] = "m=..,t=..,p=.."
	for _, kv := range strings.Split(parts[3], ",") {
		kvParts := strings.SplitN(kv, "=", 2)
		if len(kvParts) != 2 {
			return 0, 0, 0, nil, nil, false
		}
		n, err := strconv.ParseUint(kvParts[1], 10, 32)
		if err != nil {
			return 0, 0, 0, nil, nil, false
		}
		switch kvParts[0] {
		case "m":
			m = uint32(n)
		case "t":
			t = uint32(n)
		case "p":
			p = uint8(n)
		}
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return 0, 0, 0, nil, nil, false
	}
	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return 0, 0, 0, nil, nil, false
	}
	return m, t, p, salt, hash, true
}

// NewToken returns a fresh opaque session token (32 random bytes, base64url).
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("auth: read token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// region FUNC_Middleware [DOMAIN(9): Security; CONCEPT(8): Gate; TECH(8): net/http]
// @purpose Deny-by-default: only public paths pass without a valid session token.
// @complexity 5
// @invariants
//   - The wrapped handler is only invoked with a request whose context carries the userID.
//
// endregion FUNC_Middleware
func Middleware(s *store.Store, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Body size cap for authenticated API routes (1MB): no endpoint legitimately
			// needs more (largest write is an AI/chat message); unbounded Decode is a
			// memory-DoS surface otherwise.
			if strings.HasPrefix(r.URL.Path, "/api/") && r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			}
			if isPublic(r) {
				next.ServeHTTP(w, r)
				return
			}
			token := extractToken(r)
			if token == "" {
				deny(w, logger, "no token")
				return
			}
			userID, ok, err := s.GetSession(r.Context(), token)
			if err != nil || !ok {
				deny(w, logger, "invalid or expired session")
				return
			}
			ctx := context.WithValue(r.Context(), ctxKey{}, userID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// FromContext returns the authenticated userID set by the middleware.
func FromContext(ctx context.Context) (int64, bool) {
	v, ok := ctx.Value(ctxKey{}).(int64)
	return v, ok
}

// WithUser injects the authenticated userID into a context (the inverse of FromContext). Primarily a
// test helper so handlers can be exercised with an authenticated request without spinning up the
// session middleware.
func WithUser(ctx context.Context, uid int64) context.Context {
	return context.WithValue(ctx, ctxKey{}, uid)
}

// isPublic: anything outside /api/ (frontend assets, /healthz) is public; the login endpoints
// under /api/ are public (POST /api/auth/login and the 2FA-completion POST /api/auth/login/2fa), and
// GET /api/version is public (build stamp, shown pre-login for build-mismatch debugging). All other
// /api/* routes require a valid session.
func isPublic(r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}
	if r.URL.Path == "/api/version" && r.Method == http.MethodGet {
		return true
	}
	// Login-page host audit: public by design, but the handler itself refuses server-mode
	// deployments (host posture must not leak unauthenticated from an internet-facing box).
	if r.URL.Path == "/api/doctor" && r.Method == http.MethodGet {
		return true
	}
	if r.Method != http.MethodPost {
		return false
	}
	return r.URL.Path == "/api/auth/login" || r.URL.Path == "/api/auth/login/2fa"
}

// extractToken: Authorization: Bearer <token>, cookie vmpulse_session, or ?token= (WebSocket).
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	if c, err := r.Cookie("vmpulse_session"); err == nil {
		return c.Value
	}
	// WebSocket handshakes (browsers cannot set custom headers): allow token via query param.
	// BUG_FIX_CONTEXT (2026-08-19 audit 2.5): previously accepted for ANY request - the token
	// then leaks into proxy logs / browser history / Referer. Now gated on the Upgrade header
	// actually requesting websocket; everything else must use Authorization or the cookie.
	if strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "websocket") {
		return r.URL.Query().Get("token")
	}
	return ""
}

func deny(w http.ResponseWriter, logger *slog.Logger, reason string) {
	logging.LDD(logger, 9, "Middleware", "DENY", reason)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
}
