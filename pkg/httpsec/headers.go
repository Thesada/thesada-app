package httpsec

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net"
	"net/http"
)

type nonceCtxKey struct{}

// Nonce returns the per-request CSP nonce SecurityHeaders stored on ctx.
// Empty when the request did not pass through that middleware.
// in: request context. out: nonce, or "".
func Nonce(ctx context.Context) string {
	s, _ := ctx.Value(nonceCtxKey{}).(string)
	return s
}

// freshNonce is 128 bits, base64url, so it cannot break the CSP header.
func freshNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "unavailable"
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// cspPolicy is one policy for the whole app. Inline scripts and htmx's
// injected indicator style carry the per-request nonce. style attributes
// stay allowed: a handful of layout attributes cannot take a nonce.
func cspPolicy(nonce string) string {
	return "default-src 'self'; " +
		"script-src 'self' 'nonce-" + nonce + "'; " +
		"style-src 'self' 'nonce-" + nonce + "'; " +
		"style-src-attr 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'"
}

// SecurityHeaders wraps next with the standard browser security headers on
// every response, web and API alike. Strict-Transport-Security is only sent
// when the request demonstrably arrived over TLS (directly or via a trusted
// proxy, per RequestIsSecure) - browsers ignore HSTS on plain HTTP, and
// emitting it there would just be noise on LAN/dev setups.
// in: next handler, trusted proxy networks. out: wrapping handler.
func SecurityHeaders(next http.Handler, trusted []*net.IPNet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nonce := freshNonce()
		r = r.WithContext(context.WithValue(r.Context(), nonceCtxKey{}, nonce))
		h := w.Header()
		h.Set("Content-Security-Policy", cspPolicy(nonce))
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if RequestIsSecure(r, trusted) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
