// CSRF gate on the cookie-authed /api/v1 path (A1). A valid session cookie on an
// unsafe method must additionally prove same-origin intent; the bearer path and
// safe methods are exempt. Reuses the fakes / helpers in middleware_test.go.
package authmw

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"thesada.app/app/pkg/service"
)

const csrfBase = "https://app.example.com"

// runAPICSRF drives one request through APIMiddleware with a base-URL guard and
// reports the status plus whether the downstream handler saw a session.
func runAPICSRF(t *testing.T, r *http.Request) (int, *service.Session) {
	t.Helper()
	var got *service.Session
	guard := APICSRFGuard{BaseURL: csrfBase}
	rec := httptest.NewRecorder()
	APIMiddleware(&fakeAuth{sess: newSession(false, nil)}, &fakeTokens{}, guard)(
		captureSession(&got)).ServeHTTP(rec, r)
	return rec.Code, got
}

func TestAPIMiddleware_CookieUnsafe_NoSignal_403(t *testing.T) {
	r := withCookie(httptest.NewRequest(http.MethodPost, "/api/v1/devices", nil), "sess-tok")
	code, got := runAPICSRF(t, r)
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
	if got != nil {
		t.Errorf("session injected despite CSRF failure: %+v", got)
	}
}

func TestAPIMiddleware_CookieUnsafe_FetchSameOrigin_Passes(t *testing.T) {
	r := withCookie(httptest.NewRequest(http.MethodPost, "/api/v1/devices", nil), "sess-tok")
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	code, got := runAPICSRF(t, r)
	if code != http.StatusOK || got == nil {
		t.Errorf("status=%d session=%v, want 200 + session", code, got)
	}
}

func TestAPIMiddleware_CookieUnsafe_FetchSameSite_403(t *testing.T) {
	r := withCookie(httptest.NewRequest(http.MethodPost, "/api/v1/devices", nil), "sess-tok")
	r.Header.Set("Sec-Fetch-Site", "same-site") // sibling subdomain: the A1 gap
	code, _ := runAPICSRF(t, r)
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
}

func TestAPIMiddleware_CookieUnsafe_OriginMatch_Passes(t *testing.T) {
	r := withCookie(httptest.NewRequest(http.MethodPost, "/api/v1/devices", nil), "sess-tok")
	r.Header.Set("Origin", csrfBase)
	code, got := runAPICSRF(t, r)
	if code != http.StatusOK || got == nil {
		t.Errorf("status=%d session=%v, want 200 + session", code, got)
	}
}

func TestAPIMiddleware_CookieUnsafe_OriginMismatch_403(t *testing.T) {
	r := withCookie(httptest.NewRequest(http.MethodPost, "/api/v1/devices", nil), "sess-tok")
	r.Header.Set("Origin", "https://evil.example.com")
	code, _ := runAPICSRF(t, r)
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
}

func TestAPIMiddleware_CookieUnsafe_DeleteNoSignal_403(t *testing.T) {
	r := withCookie(httptest.NewRequest(http.MethodDelete, "/api/v1/alerts/1", nil), "sess-tok")
	code, _ := runAPICSRF(t, r)
	if code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", code)
	}
}

func TestAPIMiddleware_CookieSafeMethod_NoGate(t *testing.T) {
	r := withCookie(httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil), "sess-tok")
	code, got := runAPICSRF(t, r)
	if code != http.StatusOK || got == nil {
		t.Errorf("status=%d session=%v, want 200 + session (GET is exempt)", code, got)
	}
}

// Bearer on an unsafe method bypasses the CSRF gate entirely - programmatic
// clients are unaffected. No cookie is present; the token owner is injected.
func TestAPIMiddleware_BearerUnsafe_BypassesGate(t *testing.T) {
	u := &service.User{TenantID: "acme", Email: "api@example.com"}
	var got *service.Session
	guard := APICSRFGuard{BaseURL: csrfBase}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/devices", nil)
	r.Header.Set("Authorization", "Bearer good")
	rec := httptest.NewRecorder()
	APIMiddleware(&fakeAuth{}, &fakeTokens{user: u}, guard)(
		captureSession(&got)).ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || got == nil || got.User != u {
		t.Errorf("status=%d session=%v, want 200 + token owner", rec.Code, got)
	}
}
