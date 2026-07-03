package httpsec

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestSecurityHeaders covers the always-on header set, the TLS-gated HSTS
// header (direct TLS, proxy X-Forwarded-Proto, and plain-HTTP absence), and
// that the wrapped handler still runs.
func TestSecurityHeaders(t *testing.T) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})

	do := func(tlsOn bool, xfp string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "http://app/x", nil)
		if tlsOn {
			r.TLS = &tls.ConnectionState{}
		}
		if xfp != "" {
			r.Header.Set("X-Forwarded-Proto", xfp)
		}
		w := httptest.NewRecorder()
		SecurityHeaders(inner).ServeHTTP(w, r)
		return w
	}

	t.Run("always-on set + handler runs", func(t *testing.T) {
		w := do(false, "")
		if w.Code != http.StatusTeapot {
			t.Fatalf("inner handler not reached, status = %d", w.Code)
		}
		for header, want := range map[string]string{
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
			"Referrer-Policy":        "strict-origin-when-cross-origin",
		} {
			if got := w.Header().Get(header); got != want {
				t.Errorf("%s = %q, want %q", header, got, want)
			}
		}
		got := w.Header().Get("Content-Security-Policy")
		for _, directive := range []string{
			"default-src 'self'", "frame-ancestors 'none'", "base-uri 'self'", "form-action 'self'",
		} {
			if !strings.Contains(got, directive) {
				t.Errorf("CSP missing %q in %q", directive, got)
			}
		}
	})

	t.Run("hsts only over tls", func(t *testing.T) {
		if got := do(false, "").Header().Get("Strict-Transport-Security"); got != "" {
			t.Errorf("HSTS sent on plain HTTP: %q", got)
		}
		want := "max-age=31536000; includeSubDomains"
		if got := do(true, "").Header().Get("Strict-Transport-Security"); got != want {
			t.Errorf("HSTS over direct TLS = %q, want %q", got, want)
		}
		if got := do(false, "https").Header().Get("Strict-Transport-Security"); got != want {
			t.Errorf("HSTS behind TLS-terminating proxy = %q, want %q", got, want)
		}
	})
}
