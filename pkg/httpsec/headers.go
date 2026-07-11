package httpsec

import (
	"net"
	"net/http"
)

// csp is intentionally one static policy for the whole app: every asset is
// served from the app's own origin (htmx, chart.js, and app.css live under
// /static), the dashboard opens WebSockets only against location.host, and
// nothing may frame the app. 'unsafe-inline' remains for scripts because the
// HTMX templates carry templated inline <script> blocks, and for styles
// because htmx injects its indicator <style> element at runtime; tightening
// both to nonces is a follow-up that has to touch the template pipeline.
const csp = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"frame-ancestors 'none'; " +
	"base-uri 'self'; " +
	"form-action 'self'"

// SecurityHeaders wraps next with the standard browser security headers on
// every response, web and API alike. Strict-Transport-Security is only sent
// when the request demonstrably arrived over TLS (directly or via a trusted
// proxy, per RequestIsSecure) - browsers ignore HSTS on plain HTTP, and
// emitting it there would just be noise on LAN/dev setups.
// in: next handler, trusted proxy networks. out: wrapping handler.
func SecurityHeaders(next http.Handler, trusted []*net.IPNet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		if RequestIsSecure(r, trusted) {
			h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		}
		next.ServeHTTP(w, r)
	})
}
