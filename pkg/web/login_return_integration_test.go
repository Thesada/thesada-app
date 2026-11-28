//go:build integration

package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/csrf"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/totp"
)

const claimScan = "/devices/claim?device_id=thesada-0123456789ab&code=12345678"

// TestLoginReturn_ClaimScanSurvivesLogin checks that a logged-out claim scan
// lands back on the prefilled form after password and TOTP login.
// in: t. out: none.
func TestLoginReturn_ClaimScanSurvivesLogin(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	const tenant = "login-return"
	env.SeedTenant(t, tenant)
	mustWebUser(t, env, tenant, "rt-plain@a.test", "correct-horse")

	scan := getWith(srv, claimScan)
	if scan.Code != http.StatusFound {
		t.Fatalf("anonymous scan = %d, want 302", scan.Code)
	}
	loginURL := scan.Header().Get("Location")
	lu, err := url.Parse(loginURL)
	if err != nil || lu.Path != "/login" || lu.Query().Get("rt") != claimScan {
		t.Fatalf("scan redirect = %q, want /login with rt=%s", loginURL, claimScan)
	}

	page := getWith(srv, loginURL)
	if !strings.Contains(page.Body.String(), `name="rt" value="`+htmlAttr(claimScan)+`"`) {
		t.Fatalf("login form does not carry rt: %s", page.Body.String())
	}

	rec := postLoginRT(t, srv, "rt-plain@a.test", "correct-horse", claimScan)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != claimScan {
		t.Fatalf("login = %d %q, want 302 %q", rec.Code, rec.Header().Get("Location"), claimScan)
	}
	form := getWith(srv, claimScan, cookieNamed(t, rec, authmw.CookieName))
	body := form.Body.String()
	if form.Code != http.StatusOK || !strings.Contains(body, `value="thesada-0123456789ab"`) || !strings.Contains(body, `value="12345678"`) {
		t.Fatalf("claim form = %d, not prefilled: %s", form.Code, body)
	}

	raw, encoded, err := totp.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tu := mustWebUser(t, env, tenant, "rt-totp@a.test", "correct-horse")
	if err := env.Services.Auth.SetTOTPSecret(tenant, tu, encoded); err != nil {
		t.Fatal(err)
	}
	ch := postLoginRT(t, srv, "rt-totp@a.test", "correct-horse", claimScan)
	if ch.Header().Get("Location") != "/login/totp" {
		t.Fatalf("totp login = %d %q", ch.Code, ch.Header().Get("Location"))
	}
	good := postTOTP(t, srv, cookieNamed(t, ch, totpPendingCookie), totp.Code(raw, time.Now()), "", cookieNamed(t, ch, loginReturnCookie))
	if good.Code != http.StatusFound || good.Header().Get("Location") != claimScan {
		t.Fatalf("totp code = %d %q, want 302 %q", good.Code, good.Header().Get("Location"), claimScan)
	}
}

// TestLoginReturn_RefusesOffSiteTarget is the negative control: an off-site
// return target is dropped from the form and never used as the redirect.
// in: t. out: none.
func TestLoginReturn_RefusesOffSiteTarget(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	const tenant = "login-return-evil"
	env.SeedTenant(t, tenant)
	mustWebUser(t, env, tenant, "rt-evil@a.test", "correct-horse")

	for _, evil := range []string{"https://evil.example.com/devices", "//evil.example.com", `/\evil.example.com`} {
		page := getWith(srv, "/login?rt="+url.QueryEscape(evil))
		if strings.Contains(page.Body.String(), "evil.example.com") {
			t.Errorf("login form echoes off-site rt %q", evil)
		}
		rec := postLoginRT(t, srv, "rt-evil@a.test", "correct-horse", evil)
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/devices" {
			t.Errorf("login with rt %q = %d %q, want 302 /devices", evil, rec.Code, rec.Header().Get("Location"))
		}
	}
}

// TestLoginReturn_AbandonedChallengeTargetIsDropped checks that a later
// challenge without rt expires the target an abandoned claim challenge left.
// in: t. out: none.
func TestLoginReturn_AbandonedChallengeTargetIsDropped(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	const tenant = "login-return-stale"
	env.SeedTenant(t, tenant)
	raw, encoded, err := totp.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	tu := mustWebUser(t, env, tenant, "rt-stale@a.test", "correct-horse")
	if err := env.Services.Auth.SetTOTPSecret(tenant, tu, encoded); err != nil {
		t.Fatal(err)
	}
	abandoned := postLoginRT(t, srv, "rt-stale@a.test", "correct-horse", claimScan)
	stale := cookieNamed(t, abandoned, loginReturnCookie)

	ch := postLogin(t, srv, "rt-stale@a.test", "correct-horse")
	if ch.Header().Get("Location") != "/login/totp" {
		t.Fatalf("second login = %d %q, want 302 /login/totp", ch.Code, ch.Header().Get("Location"))
	}
	held := browserCookie(stale, ch, loginReturnCookie)
	done := postTOTP(t, srv, cookieNamed(t, ch, totpPendingCookie), totp.Code(raw, time.Now()), "", held)
	if done.Code != http.StatusFound || done.Header().Get("Location") != "/devices" {
		t.Fatalf("totp code = %d %q, want 302 /devices", done.Code, done.Header().Get("Location"))
	}
}

// browserCookie is the cookie a browser holds after rec: replaced, kept, or nil once expired.
// in: cookie held before, recorder, name. out: cookie or nil.
func browserCookie(held *http.Cookie, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			if c.MaxAge < 0 {
				return nil
			}
			return c
		}
	}
	return held
}

// postLoginRT submits the password form with a return target.
// in: t, handler, email, password, rt. out: recorder.
func postLoginRT(t *testing.T, srv http.Handler, email, password, rt string) *httptest.ResponseRecorder {
	t.Helper()
	tok := csrfCookie(t, srv)
	form := url.Values{"email": {email}, "password": {password}, "rt": {rt}, csrf.FormField: {tok.Value}}
	return submitForm(srv, "/login", form, []*http.Cookie{tok}, "")
}

// getWith sends one GET with cookies.
// in: handler, target, cookies. out: recorder.
func getWith(srv http.Handler, target string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// htmlAttr mirrors html/template escaping of & in an attribute value.
// in: s. out: escaped s.
func htmlAttr(s string) string {
	return strings.ReplaceAll(s, "&", "&amp;")
}
