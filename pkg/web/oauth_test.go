// OAuth handler input + helper coverage. The exchange / link /
// sign-in paths talk to an IdP + the OAuth service and belong to Phase 3+;
// these cover the pre-service guards and the open-redirect vet, all reachable
// with nil services.
package web

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// handleOIDCStart 404s an empty slug before resolving a provider.
func TestOIDCStart_EmptySlug_404(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	r := reqWithPathValue(http.MethodGet, "slug", "")
	s.handleOIDCStart(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Errorf("empty slug = %d, want 404", rec.Code)
	}
}

// handleOIDCCallback 400s when code/state are absent and the IdP did not pass
// an error param (the error-param branch renders login.html, which needs
// templates - Phase 3).
func TestOIDCCallback_MissingCodeState_400(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	r := reqWithPathValue(http.MethodGet, "slug", "kanidm")
	s.handleOIDCCallback(rec, r)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("missing code/state = %d, want 400", rec.Code)
	}
}

// handleIdentityUnlink redirects an unauthenticated caller to /login before
// touching any service.
func TestIdentityUnlink_NoSession_RedirectsLogin(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	r := reqWithPathValue(http.MethodPost, "id", "00000000-0000-0000-0000-000000000001")
	s.handleIdentityUnlink(rec, r)
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "/login" {
		t.Errorf("Location = %q, want /login", loc)
	}
}

// safeReturn passes through a vetted relative path and falls back to the
// default for open-redirect-shaped input (absolute URL, scheme-relative //,
// non-slash prefix, empty).
func TestSafeReturn(t *testing.T) {
	const fallback = "/devices"
	cases := []struct {
		in   string
		want string
	}{
		{"/settings", "/settings"},
		{"/devices/abc?tab=x", "/devices/abc?tab=x"},
		{"", fallback},
		{"//evil.example.com", fallback},
		{"http://evil.example.com", fallback},
		{"relative-no-slash", fallback},
	}
	for _, tc := range cases {
		if got := safeReturn(tc.in, fallback); got != tc.want {
			t.Errorf("safeReturn(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
