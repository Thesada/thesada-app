// Package httpsec holds small, dependency-free request-security helpers shared
// across the HTTP and WebSocket layers: deciding the cookie Secure flag and
// validating WebSocket upgrade origins. Keeping them here (rather than in
// authmw, csrf, or web) lets every layer make the same decision the same way.
package httpsec

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// RequestIsSecure reports whether the request reached the app over TLS, either
// directly (r.TLS != nil) or via a trusted reverse proxy that terminated TLS
// and set X-Forwarded-Proto. The header is only honoured when the immediate
// peer is in the trusted proxy set - same gate as ClientIP - so an arbitrary
// peer cannot spoof "https" and get Secure-flagged cookies over plain HTTP.
// in: request, trusted proxy networks. out: true when cookies should be marked Secure.
func RequestIsSecure(r *http.Request, trusted []*net.IPNet) bool {
	if r.TLS != nil {
		return true
	}
	if !ipInAny(net.ParseIP(hostOnly(r.RemoteAddr)), trusted) {
		return false
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

// SameOriginUnsafe reports whether an unsafe (state-changing) request demonstrably
// originates from the app's own pages. It trusts the browser-set Fetch Metadata
// header Sec-Fetch-Site when present - only same-origin / none pass; same-site is
// rejected because a sibling subdomain riding a SameSite=Lax cookie is exactly
// the gap being closed - and otherwise falls back to an exact Origin scheme+host
// match against baseURL. Unlike OriginAllowed, a missing Origin does NOT pass: a
// cookie-authed mutation carrying neither signal is treated as forgeable. baseURL
// is the app's public base (config.BaseURL) so the compare honors the public
// scheme even when a proxy speaks plain HTTP to the app.
// in: request, app public base URL. out: true if same-origin intent is provable.
func SameOriginUnsafe(r *http.Request, baseURL string) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "same-site", "cross-site":
		return false
	}
	// No Fetch Metadata (older browser, or a proxy stripped it): require an exact
	// Origin match. An absent Origin fails closed for unsafe methods.
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
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

// ClientIP resolves the originating client address for logging and per-IP rate
// limiting. When the immediate peer is one of the trusted proxy networks it
// walks X-Forwarded-For right-to-left and returns the first non-trusted hop -
// the real client, ignoring any client-spoofed prefix. With no trusted proxies,
// or a direct/untrusted peer, it returns the peer address.
// in: request, trusted proxy networks. out: client IP ("" if unparseable).
func ClientIP(r *http.Request, trusted []*net.IPNet) string {
	peer := hostOnly(r.RemoteAddr)
	if len(trusted) == 0 || !ipInAny(net.ParseIP(peer), trusted) {
		return peer
	}
	// Return only a parsed, re-serialised IP - never a raw header token - so an
	// X-Forwarded-For value can't carry junk into a rate-limit key, log, or email.
	for _, part := range reverseSplit(r.Header.Get("X-Forwarded-For")) {
		if ip := net.ParseIP(strings.TrimSpace(part)); ip != nil && !ipInAny(ip, trusted) {
			return ip.String()
		}
	}
	return peer
}

// hostOnly strips the port from a host:port address, handling IPv6 brackets.
// in: addr. out: host portion (addr unchanged if it carries no port).
func hostOnly(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// ipInAny reports whether ip is non-nil and falls inside any of nets.
func ipInAny(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// reverseSplit splits a comma list and returns the parts right-to-left.
func reverseSplit(s string) []string {
	parts := strings.Split(s, ",")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return parts
}
