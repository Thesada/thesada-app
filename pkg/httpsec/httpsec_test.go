package httpsec

import (
	"crypto/tls"
	"net"
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
