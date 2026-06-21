// Package csrf implements the double-submit cookie pattern for cross-site
// request forgery protection on HTMX form POSTs. A random token is written
// to a non-HttpOnly cookie on first contact; every unsafe method must echo
// that token back in the "_csrf" form field (or "X-CSRF-Token" header for
// HTMX ajax). Safe methods pass through untouched.
package csrf

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"net/http"

	"thesada.app/app/pkg/httpsec"
)

// CookieName is the double-submit cookie name.
const CookieName = "thesada_csrf"

// FormField is the hidden input name the HTML forms must submit.
const FormField = "_csrf"

// HeaderName is the ajax header name HTMX may use instead of the form field.
const HeaderName = "X-CSRF-Token"

// tokenBytes is the raw token length before base64 encoding.
const tokenBytes = 32

// ctxKey is an unexported context key holding the request's current token.
type ctxKey int

const tokenKey ctxKey = 1

// Middleware ensures every request carries a csrf cookie and verifies unsafe
// methods echo the cookie value back via form field or header. Failures return
// 403. The resolved token is placed in the request context so handlers can
// render it into forms via Token(r).
// in: none. out: http.Handler wrapper factory.
func Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ensureCookie(w, r)
			if isUnsafe(r.Method) {
				if !verify(r, token) {
					http.Error(w, "csrf token mismatch", http.StatusForbidden)
					return
				}
			}
			ctx := context.WithValue(r.Context(), tokenKey, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Token returns the csrf token attached to the request context, or "" if the
// middleware has not run for this request.
// in: request. out: base64 token or "".
func Token(r *http.Request) string {
	v := r.Context().Value(tokenKey)
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// ensureCookie reads the existing csrf cookie or mints a new one and sets it.
// in: writer, request. out: the token string now associated with the request.
func ensureCookie(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(CookieName); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		// Fail closed: with no token, unsafe methods 403 (verify rejects an
		// empty expected token) rather than ride a predictable cookie value.
		slog.Error("csrf.token_generation_failed", "err", err)
		return ""
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	http.SetCookie(w, &http.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: false,
		Secure:   httpsec.RequestIsSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

// isUnsafe reports whether the HTTP method mutates state and must be verified.
// in: method string. out: true for POST/PUT/PATCH/DELETE.
func isUnsafe(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	}
	return false
}

// verify compares the submitted token (form field or header) to the cookie
// token using a constant-time compare. Returns true on match.
// in: request, expected cookie token. out: true if submitted token matches.
func verify(r *http.Request, expected string) bool {
	submitted := r.Header.Get(HeaderName)
	if submitted == "" {
		if err := r.ParseForm(); err == nil {
			submitted = r.PostFormValue(FormField)
		}
	}
	if submitted == "" || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(submitted), []byte(expected)) == 1
}
