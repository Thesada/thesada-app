package httpsec

import (
	"crypto/tls"
	"net"
	"net/http"
	"testing"
)

// TestRequestIsSecure_TrustedProxyGate covers direct TLS, the forwarded-proto
// header honoured only from a trusted proxy peer (case-insensitive), the
// spoofed-header rejection from untrusted peers, and the plain-HTTP fallthrough.
func TestRequestIsSecure_TrustedProxyGate(t *testing.T) {
	proxyNets := mustNets(t, "10.0.0.0/8")
	cases := []struct {
		name    string
		tls     bool
		xfp     string
		peer    string
		trusted []*net.IPNet
		want    bool
	}{
		{"direct tls", true, "", "203.0.113.9:444", nil, true},
		{"xfp https from trusted proxy", false, "https", "10.0.0.2:5555", proxyNets, true},
		{"xfp HTTPS mixed case trusted", false, "HTTPS", "10.0.0.2:5555", proxyNets, true},
		{"xfp https spoofed by untrusted peer", false, "https", "203.0.113.9:444", proxyNets, false},
		{"xfp https with no trusted proxies", false, "https", "10.0.0.2:5555", nil, false},
		{"xfp http from trusted proxy", false, "http", "10.0.0.2:5555", proxyNets, false},
		{"no tls no header", false, "", "10.0.0.2:5555", proxyNets, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, _ := http.NewRequest(http.MethodGet, "http://app/x", nil)
			r.RemoteAddr = c.peer
			if c.tls {
				r.TLS = &tls.ConnectionState{}
			}
			if c.xfp != "" {
				r.Header.Set("X-Forwarded-Proto", c.xfp)
			}
			if got := RequestIsSecure(r, c.trusted); got != c.want {
				t.Errorf("RequestIsSecure(tls=%v xfp=%q peer=%s) = %v, want %v", c.tls, c.xfp, c.peer, got, c.want)
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

// mustNets parses CIDR/IP strings into networks for the ClientIP tests.
func mustNets(t *testing.T, specs ...string) []*net.IPNet {
	t.Helper()
	var out []*net.IPNet
	for _, s := range specs {
		if _, n, err := net.ParseCIDR(s); err == nil {
			out = append(out, n)
			continue
		}
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("mustNets: bad spec %q", s)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out
}

// TestClientIP covers RemoteAddr fallback, IPv6, and trusted-proxy XFF
// resolution including the spoof-resistant right-to-left walk.
func TestClientIP(t *testing.T) {
	trusted := mustNets(t, "10.0.0.0/8")
	cases := []struct {
		name    string
		remote  string
		xff     string
		trusted []*net.IPNet
		want    string
	}{
		{"no_trusted_uses_remote", "1.2.3.4:5678", "203.0.113.5", nil, "1.2.3.4"},
		{"no_trusted_ipv6", "[2001:db8::1]:443", "", nil, "2001:db8::1"},
		{"untrusted_peer_ignores_xff", "8.8.8.8:1", "203.0.113.5", trusted, "8.8.8.8"},
		{"trusted_peer_no_xff_uses_peer", "10.0.0.1:1", "", trusted, "10.0.0.1"},
		{"trusted_peer_returns_client", "10.0.0.1:1", "203.0.113.5", trusted, "203.0.113.5"},
		{"spoofed_prefix_ignored", "10.0.0.1:1", "9.9.9.9, 203.0.113.5", trusted, "203.0.113.5"},
		{"multi_trusted_hop_skipped", "10.0.0.2:1", "203.0.113.5, 10.0.0.9", trusted, "203.0.113.5"},
		{"garbage_token_skipped", "10.0.0.1:1", "not-an-ip, 203.0.113.5", trusted, "203.0.113.5"},
		{"all_garbage_falls_to_peer", "10.0.0.1:1", "junk, also junk", trusted, "10.0.0.1"},
		{"xff_ipv6_normalised", "10.0.0.1:1", "2001:DB8::1", trusted, "2001:db8::1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &http.Request{RemoteAddr: tc.remote, Header: http.Header{}}
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := ClientIP(r, tc.trusted); got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestSameOriginUnsafe covers the cookie-authed unsafe-method gate: the
// Fetch-Metadata header decides when present (same-origin/none pass, same-site/
// cross-site fail), and otherwise an exact Origin scheme+host match against
// baseURL is required - a missing or foreign Origin fails closed.
func TestSameOriginUnsafe(t *testing.T) {
	const base = "https://app.example.com"
	cases := []struct {
		name      string
		fetchSite string
		origin    string
		want      bool
	}{
		{"fetch same-origin", "same-origin", "", true},
		{"fetch none", "none", "", true},
		{"fetch same-site sibling", "same-site", "https://evil.example.com", false},
		{"fetch cross-site", "cross-site", "https://evil.com", false},
		{"no fetch, origin match", "", "https://app.example.com", true},
		{"no fetch, origin host mismatch", "", "https://evil.example.com", false},
		{"no fetch, origin scheme mismatch", "", "http://app.example.com", false},
		{"no fetch, origin absent", "", "", false},
		{"no fetch, origin suffix trick", "", "https://app.example.com.evil.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodPost, base+"/api/v1/x", nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			if c.fetchSite != "" {
				r.Header.Set("Sec-Fetch-Site", c.fetchSite)
			}
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if got := SameOriginUnsafe(r, base); got != c.want {
				t.Errorf("SameOriginUnsafe = %v, want %v", got, c.want)
			}
		})
	}
}
