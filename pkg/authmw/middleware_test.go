// Cookie/bearer resolution contracts for Middleware + APIMiddleware, plus the
// security attributes of the session cookie itself. These paths call the auth
// services, so they run against small fakes (SessionValidator / TokenValidator)
// - no DB, default test lane. The route-guard + context helpers are covered in
// authmw_test.go / apiauth_test.go.
package authmw

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
)

// ── fakes ──────────────────────────────────────────────────────────────

type fakeAuth struct {
	sess     *service.Session
	err      error
	gotToken string // the token passed to ValidateSession (proves what was validated)
	calls    int
}

func (f *fakeAuth) ValidateSession(token string) (*service.Session, error) {
	f.calls++
	f.gotToken = token
	return f.sess, f.err
}

type fakeTokens struct {
	user *service.User
	err  error
}

func (f *fakeTokens) ValidateToken(string) (*service.User, error) { return f.user, f.err }

// captureSession records the session the downstream handler observed.
func captureSession(got **service.Session) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		*got = CurrentSession(r)
		w.WriteHeader(http.StatusOK)
	}
}

func cookieNamed(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func withCookie(r *http.Request, val string) *http.Request {
	r.AddCookie(&http.Cookie{Name: CookieName, Value: val})
	return r
}

// ── Middleware (web) ───────────────────────────────────────────────────

func TestMiddleware_NoCookie_StaysAnonymous(t *testing.T) {
	fa := &fakeAuth{sess: newSession(false, nil)}
	var got *service.Session
	Middleware(fa, nil)(captureSession(&got)).ServeHTTP(
		httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil))
	if got != nil {
		t.Errorf("session = %+v, want anonymous", got)
	}
	if fa.calls != 0 {
		t.Errorf("ValidateSession called %d times, want 0 (no cookie)", fa.calls)
	}
}

func TestMiddleware_InvalidCookie_SilentlyAnonymous(t *testing.T) {
	fa := &fakeAuth{err: errors.New("expired")}
	var got *service.Session
	rec := httptest.NewRecorder()
	Middleware(fa, nil)(captureSession(&got)).ServeHTTP(rec, withCookie(httptest.NewRequest(http.MethodGet, "/", nil), "bad"))
	if got != nil {
		t.Errorf("session = %+v, want anonymous on validation failure", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (request proceeds anonymously)", rec.Code)
	}
}

func TestMiddleware_ValidCookie_InjectsSession(t *testing.T) {
	sess := newSession(false, nil)
	fa := &fakeAuth{sess: sess}
	var got *service.Session
	Middleware(fa, nil)(captureSession(&got)).ServeHTTP(
		httptest.NewRecorder(), withCookie(httptest.NewRequest(http.MethodGet, "/", nil), "raw-token"))
	if got != sess {
		t.Errorf("injected session = %+v, want %+v", got, sess)
	}
	if fa.gotToken != "raw-token" {
		t.Errorf("validated token = %q, want the cookie value", fa.gotToken)
	}
}

func TestMiddleware_RotatedToken_WritesSecureCookie(t *testing.T) {
	sess := newSession(false, nil)
	sess.NewToken = "rotated-token"
	sess.NewExpires = time.Now().Add(time.Hour)
	fa := &fakeAuth{sess: sess}

	rec := httptest.NewRecorder()
	req := withCookie(httptest.NewRequest(http.MethodGet, "/", nil), "old")
	req.Header.Set("X-Forwarded-Proto", "https") // TLS-terminated upstream
	Middleware(fa, testProxyNets(t))(okHandler()).ServeHTTP(rec, req)

	c := cookieNamed(rec.Result(), CookieName)
	if c == nil {
		t.Fatal("no session cookie written on rotation")
	}
	if c.Value != "rotated-token" {
		t.Errorf("cookie value = %q, want rotated-token", c.Value)
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie flags: Secure=%v HttpOnly=%v SameSite=%v", c.Secure, c.HttpOnly, c.SameSite)
	}
}

func TestMiddleware_RotatedToken_InsecureOverPlainHTTP(t *testing.T) {
	sess := newSession(false, nil)
	sess.NewToken = "rotated"
	sess.NewExpires = time.Now().Add(time.Hour)
	rec := httptest.NewRecorder()
	Middleware(&fakeAuth{sess: sess}, nil)(okHandler()).ServeHTTP(
		rec, withCookie(httptest.NewRequest(http.MethodGet, "/", nil), "old"))
	c := cookieNamed(rec.Result(), CookieName)
	if c == nil || c.Secure {
		t.Errorf("plain-HTTP rotation cookie Secure=%v, want false", c != nil && c.Secure)
	}
}

func TestMiddleware_NoRotation_NoCookieWritten(t *testing.T) {
	rec := httptest.NewRecorder()
	Middleware(&fakeAuth{sess: newSession(false, nil)}, nil)(okHandler()).ServeHTTP(
		rec, withCookie(httptest.NewRequest(http.MethodGet, "/", nil), "tok"))
	if c := cookieNamed(rec.Result(), CookieName); c != nil {
		t.Errorf("cookie written without rotation: %+v", c)
	}
}

// ── APIMiddleware (JSON) ───────────────────────────────────────────────

func TestAPIMiddleware_BearerValid_InjectsUserWithoutCookie(t *testing.T) {
	u := &service.User{ID: uuid.New(), TenantID: "acme", Email: "api@example.com"}
	fa := &fakeAuth{} // cookie path must not be consulted
	var got *service.Session
	req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	APIMiddleware(fa, &fakeTokens{user: u}, APICSRFGuard{}, nil)(captureSession(&got)).ServeHTTP(httptest.NewRecorder(), req)
	if got == nil || got.User != u {
		t.Fatalf("injected user = %+v, want token owner", got)
	}
	if fa.calls != 0 {
		t.Errorf("cookie ValidateSession called %d times, want 0 (bearer wins)", fa.calls)
	}
}

func TestAPIMiddleware_BearerInvalid_FallsBackToCookie(t *testing.T) {
	sess := newSession(false, nil)
	fa := &fakeAuth{sess: sess}
	var got *service.Session
	req := withCookie(httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil), "cookie-tok")
	req.Header.Set("Authorization", "Bearer bad-token")
	APIMiddleware(fa, &fakeTokens{err: errors.New("revoked")}, APICSRFGuard{}, nil)(captureSession(&got)).ServeHTTP(httptest.NewRecorder(), req)
	if got != sess {
		t.Errorf("session = %+v, want cookie fallback", got)
	}
	if fa.gotToken != "cookie-tok" {
		t.Errorf("validated token = %q, want cookie value", fa.gotToken)
	}
}

func TestAPIMiddleware_NoCredentials_Anonymous(t *testing.T) {
	var got *service.Session
	rec := httptest.NewRecorder()
	APIMiddleware(&fakeAuth{}, &fakeTokens{}, APICSRFGuard{}, nil)(captureSession(&got)).ServeHTTP(
		rec, httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil))
	if got != nil {
		t.Errorf("session = %+v, want anonymous", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestAPIMiddleware_CookieRotation_RefreshesCookie(t *testing.T) {
	sess := newSession(false, nil)
	sess.NewToken = "rotated"
	sess.NewExpires = time.Now().Add(time.Hour)
	rec := httptest.NewRecorder()
	req := withCookie(httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil), "old")
	req.Header.Set("X-Forwarded-Proto", "https")
	APIMiddleware(&fakeAuth{sess: sess}, &fakeTokens{}, APICSRFGuard{}, testProxyNets(t))(okHandler()).ServeHTTP(rec, req)
	c := cookieNamed(rec.Result(), CookieName)
	if c == nil || c.Value != "rotated" || !c.Secure {
		t.Errorf("rotation cookie = %+v, want refreshed+secure", c)
	}
}

// ── cookie writers ─────────────────────────────────────────────────────

func TestSetSessionCookie_SecurityAttributes(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "tok", time.Now().Add(time.Hour), true)
	c := cookieNamed(rec.Result(), CookieName)
	if c == nil {
		t.Fatal("no cookie")
	}
	if c.Value != "tok" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("cookie = %+v, want HttpOnly+Secure+Lax+Path=/", c)
	}
}

func TestSetSessionCookie_InsecureFlagFollowsTransport(t *testing.T) {
	rec := httptest.NewRecorder()
	SetSessionCookie(rec, "tok", time.Now().Add(time.Hour), false)
	if c := cookieNamed(rec.Result(), CookieName); c == nil || c.Secure {
		t.Errorf("Secure = %v, want false for plain HTTP", c != nil && c.Secure)
	}
}

func TestClearSessionCookie_ExpiresImmediately(t *testing.T) {
	rec := httptest.NewRecorder()
	ClearSessionCookie(rec, true)
	c := cookieNamed(rec.Result(), CookieName)
	if c == nil {
		t.Fatal("no cookie")
	}
	if c.Value != "" || c.MaxAge >= 0 {
		t.Errorf("cleared cookie = %+v, want empty value + negative MaxAge", c)
	}
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cleared cookie must keep HttpOnly+Secure+Lax to attribute-match: %+v", c)
	}
}

func okHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }
}

// testProxyNets marks httptest's default RemoteAddr (192.0.2.1) as a trusted
// proxy so X-Forwarded-Proto is honoured in the rotation tests.
func testProxyNets(t *testing.T) []*net.IPNet {
	t.Helper()
	_, n, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatalf("parse test proxy net: %v", err)
	}
	return []*net.IPNet{n}
}
