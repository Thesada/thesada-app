// Package csrf implements signed double-submit cookie CSRF protection for HTMX POSTs.
// Tokens are HMAC-signed so a cookie planted by a sibling subdomain fails verification
// and is replaced rather than trusted.
package csrf

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"thesada.app/app/pkg/httpsec"
)

// CookieName is the double-submit cookie name.
const CookieName = "thesada_csrf"

// FormField is the hidden input name the HTML forms must submit.
const FormField = "_csrf"

// HeaderName is the ajax header name HTMX may use instead of the form field.
const HeaderName = "X-CSRF-Token"

// tokenBytes is the raw random length before base64 encoding and signing.
const tokenBytes = 32

// ctxKey is an unexported context key holding the request's current token.
type ctxKey int

const tokenKey ctxKey = 1

// Middleware ensures every request carries a signed CSRF cookie and verifies
// unsafe methods echo the value back (form field or header); failures return 403.
// in: HMAC secret, trusted proxy networks (for the cookie Secure decision).
// out: http.Handler wrapper factory.
func Middleware(secret []byte, trusted []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ensureCookie(w, r, secret, trusted)
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
// in: request. out: signed token or "".
func Token(r *http.Request) string {
	v := r.Context().Value(tokenKey)
	if v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

// ensureCookie returns the request's CSRF token, minting a fresh signed one when
// absent or invalid (attacker-planted cookies fail the signature check and are replaced).
// in: writer, request, HMAC secret, trusted proxies. out: the token now bound to the request.
func ensureCookie(w http.ResponseWriter, r *http.Request, secret []byte, trusted []*net.IPNet) string {
	if c, err := r.Cookie(CookieName); err == nil && validToken(secret, c.Value) {
		return c.Value
	}
	token, err := mint(secret)
	if err != nil {
		// Fail closed: with no token, unsafe methods 403 (verify rejects an
		// empty expected token) rather than ride a predictable cookie value.
		slog.Error("csrf.token_generation_failed", "err", err)
		return ""
	}
	http.SetCookie(w, &http.Cookie{
		Name:  CookieName,
		Value: token,
		Path:  "/",
		// HttpOnly: the token reaches JS via the CSRFToken template var, nothing
		// reads the cookie client-side, so it does not need to be scriptable.
		HttpOnly: true,
		Secure:   httpsec.RequestIsSecure(r, trusted),
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

// mint generates a random token body and appends its HMAC signature, joined by
// a dot: "<base64 random>.<base64 hmac>".
// in: HMAC secret. out: signed token, error from crypto/rand.
func mint(secret []byte) (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(buf)
	return body + "." + sign(secret, body), nil
}

// sign returns the base64 HMAC-SHA256 of body under secret.
// in: secret, message body. out: base64 signature.
func sign(secret []byte, body string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// validToken reports whether value is a well-formed "<body>.<sig>" token whose
// signature verifies under secret, in constant time over the signature compare.
// in: secret, candidate token. out: true if the signature is valid.
func validToken(secret []byte, value string) bool {
	i := strings.LastIndexByte(value, '.')
	if i <= 0 || i == len(value)-1 {
		return false
	}
	body, sig := value[:i], value[i+1:]
	return subtle.ConstantTimeCompare([]byte(sig), []byte(sign(secret, body))) == 1
}

// HasValidToken reports whether the request carries a signed CSRF token in the
// X-CSRF-Token header that both verifies under secret and matches the
// double-submit cookie. It mints nothing and writes no cookie: the /api/v1 tree
// uses it as the interoperable escape hatch so a cookie-authed browser client
// can prove same-origin intent on an unsafe method without routing through the
// HTMX Middleware.
// in: request, HMAC secret. out: true if a valid matching token is present.
func HasValidToken(r *http.Request, secret []byte) bool {
	c, err := r.Cookie(CookieName)
	if err != nil || !validToken(secret, c.Value) {
		return false
	}
	submitted := r.Header.Get(HeaderName)
	return submitted != "" && subtle.ConstantTimeCompare([]byte(submitted), []byte(c.Value)) == 1
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

// verify compares the submitted token (form field or header) to the expected cookie
// token using a constant-time compare.
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
