package httpsec

import (
	"crypto/tls"
	"net/http"
	"testing"
)

// TestRequestIsSecure covers direct TLS, the proxy forwarded-proto header
// (case-insensitive), and the plain-HTTP fallthrough.
func TestRequestIsSecure(t *testing.T) {
	cases := []struct {
		name string
		tls  bool
		xfp  string
		want bool
	}{
		{"direct tls", true, "", true},
		{"xfp https", false, "https", true},
		{"xfp HTTPS mixed case", false, "HTTPS", true},
		{"xfp http", false, "http", false},
		{"no tls no header", false, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "http://app/x", nil)
			if c.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if c.xfp != "" {
				r.Header.Set("X-Forwarded-Proto", c.xfp)
			}
			if got := RequestIsSecure(r); got != c.want {
				t.Errorf("RequestIsSecure(tls=%v xfp=%q) = %v, want %v", c.tls, c.xfp, got, c.want)
			}
		})
	}
}

// TestOriginAllowed covers the same-origin pass, exact-host match, the
// substring-suffix hijack attempt, scheme mismatch, port handling, and the
// missing-Origin (non-browser) pass.
func TestOriginAllowed(t *testing.T) {
	const base = "https://app.thesada.app"
	cases := []struct {
		name   string
		origin string
		base   string
		want   bool
	}{
		{"missing origin", "", base, true},
		{"exact match", "https://app.thesada.app", base, true},
		{"suffix hijack", "https://app.thesada.app.evil.com", base, false},
		{"prefix hijack", "https://evil.app.thesada.app", base, false},
		{"scheme mismatch", "http://app.thesada.app", base, false},
		{"other host", "https://other.com", base, false},
		{"garbage origin", "://::::", base, false},
		{"localhost dev", "http://localhost:8080", "http://localhost:8080", true},
		{"localhost wrong port", "http://localhost:9999", "http://localhost:8080", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "http://app/ws", nil)
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if got := OriginAllowed(r, c.base); got != c.want {
				t.Errorf("OriginAllowed(%q, %q) = %v, want %v", c.origin, c.base, got, c.want)
			}
		})
	}
}
