// Package authmw provides session cookie middleware and request-context helpers
// for resolving the current authenticated user in HTTP handlers.
package authmw

import (
	"context"
	"net/http"
	"time"

	"thesada.app/app/pkg/httpsec"
	"thesada.app/app/pkg/service"
)

// CookieName is the cookie that carries the raw session token.
const CookieName = "thesada_session"

// ctxKey is an unexported type to avoid collisions in context.WithValue.
type ctxKey int

const sessionKey ctxKey = 1

// SessionValidator resolves a raw session token into a *service.Session.
// *service.AuthService satisfies it; narrowing to the interface keeps the
// middleware unit-testable without a database.
type SessionValidator interface {
	ValidateSession(token string) (*service.Session, error)
}

// Middleware resolves the session cookie and puts the *Session in the request
// context. Missing or invalid cookies are silently dropped; handlers call
// CurrentUser / CurrentSession / EffectiveTenantID to inspect.
//
// When ValidateSession rotated the underlying token (sess.NewToken non-empty),
// the middleware writes the fresh cookie on the response before invoking the
// next handler. The Secure flag follows the request transport: TLS-terminated
// requests get Secure=true, plain HTTP loopback dev gets false. Plain HTTP
// requests behind a TLS-terminating reverse proxy are detected by the
// X-Forwarded-Proto header so the cookie keeps the Secure flag end-to-end.
// in: AuthService. out: http.Handler wrapper.
func Middleware(auth SessionValidator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c, err := r.Cookie(CookieName)
			if err != nil || c.Value == "" {
				next.ServeHTTP(w, r)
				return
			}
			sess, err := auth.ValidateSession(c.Value)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}
			if sess.NewToken != "" {
				SetSessionCookie(w, sess.NewToken, sess.NewExpires, httpsec.RequestIsSecure(r))
			}
			ctx := context.WithValue(r.Context(), sessionKey, sess)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CurrentSession returns the full *service.Session from the request context,
// or nil if the request is unauthenticated.
// in: request. out: *service.Session or nil.
func CurrentSession(r *http.Request) *service.Session {
	v := r.Context().Value(sessionKey)
	if v == nil {
		return nil
	}
	s, ok := v.(*service.Session)
	if !ok {
		return nil
	}
	return s
}

// CurrentUser returns the authenticated user from the request context, or nil.
// Back-compat shim on top of CurrentSession for existing handler callers.
// in: request. out: *service.User or nil.
func CurrentUser(r *http.Request) *service.User {
	s := CurrentSession(r)
	if s == nil {
		return nil
	}
	return s.User
}

// EffectiveTenantID returns the tenant id that the request's service-layer
// queries should be scoped to. For a regular user it is always their own
// tenant. For a super-admin who has set an impersonated tenant via
// /admin/impersonate, it is the impersonated tenant. Anonymous requests
// return "" and callers must guard - typically by going through RequireAuth
// before calling this.
// in: request. out: effective tenant slug, or "" if anonymous.
func EffectiveTenantID(r *http.Request) string {
	s := CurrentSession(r)
	if s == nil || s.User == nil {
		return ""
	}
	if s.User.IsSuperAdmin && s.ImpersonatedTenantID != nil && *s.ImpersonatedTenantID != "" {
		return *s.ImpersonatedTenantID
	}
	return s.User.TenantID
}

// RequireAuth wraps a handler and redirects unauthenticated requests to /login.
// in: handler. out: wrapper http.HandlerFunc.
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if CurrentUser(r) == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// RequireSuperAdmin wraps a handler and returns 404 for anyone not marked
// is_super_admin on the users row. Used to gate the /admin route tree.
// We return 404 rather than 403 so the admin surface does not advertise its
// existence to tenant-scoped users who shouldn't know it's there.
// in: handler. out: wrapper http.HandlerFunc.
func RequireSuperAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := CurrentUser(r)
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if !u.IsSuperAdmin {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

// SetSessionCookie writes the session cookie with sensible defaults.
// in: writer, raw token, expiry time, whether to mark secure (HTTPS). out: none.
func SetSessionCookie(w http.ResponseWriter, token string, expires time.Time, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie expires the session cookie immediately. Secure matches the
// issuing cookie (httpsec.RequestIsSecure) so the deletion attribute-matches.
// in: writer, secure flag. out: none.
func ClearSessionCookie(w http.ResponseWriter, secure bool) {
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}
