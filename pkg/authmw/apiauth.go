// API-surface auth for the JSON /api/v1 tree. The web gates (RequireAuth /
// RequireSuperAdmin) 302-redirect or 404 to fit a browser; a JSON client wants
// a truthful status code. APIMiddleware resolves a bearer token OR the session
// cookie into the same request-context *Session the web path uses, and the
// JSON guards answer an unauthenticated / unauthorized caller with 401 / 403.
package authmw

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"thesada.app/app/pkg/csrf"
	"thesada.app/app/pkg/httpsec"
	"thesada.app/app/pkg/service"
)

// APICSRFGuard supplies what the cookie-branch CSRF check needs: the app's public
// base URL (for the same-origin fallback) and the cookie-signing secret (for the
// double-submit token escape hatch). It is consulted only for cookie-authed
// unsafe methods; the bearer path never reaches it.
type APICSRFGuard struct {
	BaseURL string
	Secret  []byte
}

// allowCookieUnsafe reports whether a cookie-authed unsafe request proves
// same-origin intent - a browser Fetch-Metadata / Origin signal, or a valid
// double-submit CSRF token - and may therefore mutate state.
// in: request. out: true if the mutation is allowed.
func (g APICSRFGuard) allowCookieUnsafe(r *http.Request) bool {
	return httpsec.SameOriginUnsafe(r, g.BaseURL) || csrf.HasValidToken(r, g.Secret)
}

// isUnsafeMethod reports whether the method mutates state and thus needs a CSRF
// check on the cookie-authed API path (the bearer path is exempt).
// in: method. out: true for POST/PUT/PATCH/DELETE.
func isUnsafeMethod(m string) bool {
	switch m {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// APIMiddleware resolves the caller for a JSON API request and stores the
// resolved *service.Session under the same context key the web Middleware uses
// (so CurrentUser / CurrentSession / EffectiveTenantID work unchanged).
//
// Two credential sources, bearer first:
//  1. Authorization: Bearer <token>  -> ApiTokenService.ValidateToken
//  2. the thesada_session cookie      -> AuthService.ValidateSession
//
// Either miss is silent - the route guards decide whether anonymous is
// allowed. A rotated session cookie is refreshed on the response, same as the
// web path. Bearer-authed tokens carry no impersonation (API tokens are
// user-bound), so EffectiveTenantID resolves to the token owner's tenant.
//
// Cookie-authed unsafe methods (POST/PUT/PATCH/DELETE) additionally pass through
// csrfGuard: SameSite=Lax does not stop a same-site sibling subdomain, so the
// request must prove same-origin intent (Fetch-Metadata / Origin, or a
// double-submit CSRF token) or it is rejected 403. The bearer path is exempt.
// in: AuthService, ApiTokenService, cookie-path CSRF guard. out: http.Handler wrapper.
// TokenValidator resolves a raw bearer token into the owning *service.User.
// *service.ApiTokenService satisfies it; the interface keeps APIMiddleware
// unit-testable without a database.
type TokenValidator interface {
	ValidateToken(token string) (*service.User, error)
}

func APIMiddleware(auth SessionValidator, tokens TokenValidator, csrfGuard APICSRFGuard) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if tok := BearerToken(r); tok != "" {
				if u, err := tokens.ValidateToken(tok); err == nil {
					ctx := context.WithValue(r.Context(), sessionKey, &service.Session{User: u})
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
			if c, err := r.Cookie(CookieName); err == nil && c.Value != "" {
				if sess, err := auth.ValidateSession(c.Value); err == nil {
					// SameSite=Lax leaves a same-site sibling-subdomain CSRF gap and
					// readJSON ignores Content-Type, so a cookie-authed unsafe method
					// must additionally prove same-origin intent. Bearer callers never
					// reach here, so programmatic clients are unaffected.
					if isUnsafeMethod(r.Method) && !csrfGuard.allowCookieUnsafe(r) {
						writeJSONError(w, http.StatusForbidden, "csrf verification required")
						return
					}
					if sess.NewToken != "" {
						SetSessionCookie(w, sess.NewToken, sess.NewExpires, httpsec.RequestIsSecure(r))
					}
					ctx := context.WithValue(r.Context(), sessionKey, sess)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// BearerToken extracts the token from an "Authorization: Bearer <token>"
// header, or "" if the header is absent or malformed. Exported so handlers
// (e.g. /api/v1 logout) can recover the raw token to revoke it.
// in: request. out: raw token or "".
func BearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) > len(prefix) && strings.EqualFold(h[:len(prefix)], prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// writeJSONError writes a {"error": msg} body with the given status code.
// in: writer, http status, message. out: none (best-effort write).
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// RequireAuthJSON wraps a handler and answers an unauthenticated caller with a
// JSON 401 - the API analogue of RequireAuth's redirect-to-login.
// in: handler. out: wrapper http.HandlerFunc.
func RequireAuthJSON(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if CurrentUser(r) == nil {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next(w, r)
	}
}

// RequireSuperAdminJSON wraps a handler: 401 for an anonymous caller, 403 for
// an authenticated non-super-admin. Unlike the web RequireSuperAdmin (which
// 404s to hide the admin surface), the JSON API is an explicit programmatic
// contract, so it returns a truthful 403.
// in: handler. out: wrapper http.HandlerFunc.
func RequireSuperAdminJSON(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := CurrentUser(r)
		if u == nil {
			writeJSONError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if !u.IsSuperAdmin {
			writeJSONError(w, http.StatusForbidden, "super-admin required")
			return
		}
		next(w, r)
	}
}
