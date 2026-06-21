// Package httpsec holds small, dependency-free request-security helpers shared
// across the HTTP and WebSocket layers: deciding the cookie Secure flag and
// validating WebSocket upgrade origins. Keeping them here (rather than in
// authmw, csrf, or web) lets every layer make the same decision the same way.
package httpsec

import (
	"net/http"
	"net/url"
	"strings"
)

// RequestIsSecure reports whether the request reached the app over TLS, either
// directly (r.TLS != nil) or via a reverse proxy that terminated TLS and set
// the standard X-Forwarded-Proto header. Both the session and CSRF cookies use
// this so their Secure flag stays consistent end-to-end behind HAProxy.
// in: request. out: true when cookies should be marked Secure.
func RequestIsSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// OriginAllowed reports whether a WebSocket upgrade request's Origin is allowed.
// A missing Origin (non-browser client, or a same-origin request that omits it)
// passes; otherwise the Origin's scheme and host must match the app's public
// base URL exactly. The exact host compare (not a substring match) is what
// blocks cross-site WebSocket hijacking: a hostile page on app.example.com.evil
// must not be treated as same-origin with app.example.com. Origin is compared
// against BaseURL, not r.Host, so the public scheme is honored even when
// HAProxy speaks plain HTTP to the app.
// in: request, the app's public base URL. out: true if the upgrade is allowed.
func OriginAllowed(r *http.Request, baseURL string) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	o, err := url.Parse(origin)
	if err != nil || o.Host == "" {
		return false
	}
	b, err := url.Parse(baseURL)
	if err != nil || b.Host == "" {
		return false
	}
	return strings.EqualFold(o.Scheme, b.Scheme) && strings.EqualFold(o.Host, b.Host)
}
