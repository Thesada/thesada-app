//go:build integration

package web

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/csrf"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/totp"
)

// TestTOTPWeb_EnrolledLoginNeedsACodeAndSettingsCanTurnItOff checks the browser TOTP contract.
// in: t. out: none.
func TestTOTPWeb_EnrolledLoginNeedsACodeAndSettingsCanTurnItOff(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	const tenant = "totp-web"
	env.SeedTenant(t, tenant)
	auth := env.Services.Auth

	raw, encoded, err := totp.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	u := mustWebUser(t, env, tenant, "totp-web@a.test", "correct-horse")
	if err := auth.SetTOTPSecret(tenant, u, encoded); err != nil {
		t.Fatal(err)
	}

	rec := postLogin(t, srv, "totp-web@a.test", "correct-horse")
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login/totp" {
		t.Fatalf("login = %d %s", rec.Code, rec.Header().Get("Location"))
	}
	pending := cookieNamed(t, rec, totpPendingCookie)
	badCode := "000000"
	if badCode == totp.Code(raw, time.Now()) {
		badCode = "111111"
	}
	bad := postTOTP(t, srv, pending, badCode, "")
	if bad.Code != http.StatusOK || !strings.Contains(bad.Body.String(), "That code is not valid.") {
		t.Fatalf("bad code = %d %s", bad.Code, bad.Body.String())
	}
	good := postTOTP(t, srv, pending, totp.Code(raw, time.Now()), "")
	if good.Code != http.StatusFound || good.Header().Get("Location") != "/devices" {
		t.Fatalf("good code = %d %s", good.Code, good.Header().Get("Location"))
	}

	cu := mustWebUser(t, env, tenant, "totp-corrupt@a.test", "correct-horse")
	if err := auth.SetTOTPSecret(tenant, cu, "!!!"); err != nil {
		t.Fatal(err)
	}
	crec := postLogin(t, srv, "totp-corrupt@a.test", "correct-horse")
	cpend := cookieNamed(t, crec, totpPendingCookie)
	cfail := postTOTP(t, srv, cpend, "123456", "")
	if cfail.Code != http.StatusInternalServerError {
		t.Fatalf("corrupt secret = %d, want 500", cfail.Code)
	}

	expired := postTOTP(t, srv, &http.Cookie{Name: totpPendingCookie, Value: "not-a-challenge"}, "123456", "")
	if expired.Code != http.StatusFound || expired.Header().Get("Location") != "/login" {
		t.Fatalf("expired = %d %s, want 302 /login", expired.Code, expired.Header().Get("Location"))
	}

	plain := mustWebUser(t, env, tenant, "totp-enroll@a.test", "correct-horse")
	tok, _, err := auth.CreateSession(tenant, plain, "password", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	session := &http.Cookie{Name: authmw.CookieName, Value: tok}
	begin := postAuthed(t, srv, "/settings/totp/begin", url.Values{}, session, "")
	if begin.Code != http.StatusSeeOther || !strings.Contains(begin.Header().Get("Location"), "totp-setup") {
		t.Fatalf("begin = %d %s", begin.Code, begin.Header().Get("Location"))
	}
	setup := cookieNamed(t, begin, totpSetupCookie)
	key, err := totp.DecodeKey(setup.Value)
	if err != nil {
		t.Fatal(err)
	}
	confirm := postAuthed(t, srv, "/settings/totp/confirm", url.Values{"code": {totp.Code(key, time.Now())}}, session, "", setup)
	if confirm.Code != http.StatusSeeOther || !strings.Contains(confirm.Header().Get("Location"), "saved=totp") {
		t.Fatalf("confirm = %d %s", confirm.Code, confirm.Header().Get("Location"))
	}
	disable := postAuthed(t, srv, "/settings/totp/disable", url.Values{"code": {totp.Code(key, time.Now())}}, session, "")
	if disable.Code != http.StatusSeeOther || !strings.Contains(disable.Header().Get("Location"), "saved=totp") {
		t.Fatalf("disable = %d %s", disable.Code, disable.Header().Get("Location"))
	}

	nopw := mustWebUser(t, env, tenant, "totp-oidc@a.test", "")
	ntok, _, err := auth.CreateSession(tenant, nopw, "oidc", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	denied := postAuthed(t, srv, "/settings/totp/begin", url.Values{}, &http.Cookie{Name: authmw.CookieName, Value: ntok}, "")
	if denied.Code != http.StatusForbidden {
		t.Fatalf("passwordless enroll = %d, want 403", denied.Code)
	}

	limited := false
	for i := 0; i < 40; i++ {
		rec := postTOTP(t, srv, &http.Cookie{Name: totpPendingCookie, Value: "x"}, "123456", "203.0.113.50:9")
		if rec.Code == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("totp finish was not rate limited")
	}
}

// mustWebUser seeds a user and, when password is set, a password hash.
// in: t, env, tenant, email, password. out: user id.
func mustWebUser(t *testing.T, env *servicetest.Env, tenant, email, password string) uuid.UUID {
	t.Helper()
	u, err := env.Services.Auth.CreateUser(tenant, email, email, false)
	if err != nil {
		t.Fatal(err)
	}
	if password != "" {
		if err := env.Services.Auth.SetPassword(tenant, u.ID, password); err != nil {
			t.Fatal(err)
		}
	}
	return u.ID
}

// csrfCookie mints a signed token the way a browser gets one from a safe GET.
// in: t, handler. out: csrf cookie.
func csrfCookie(t *testing.T, srv http.Handler) *http.Cookie {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/login", nil))
	for _, c := range rec.Result().Cookies() {
		if c.Name == csrf.CookieName {
			return c
		}
	}
	t.Fatal("csrf cookie missing")
	return nil
}

// postLogin submits the password form with a fresh CSRF token.
// in: t, handler, email, password. out: recorder.
func postLogin(t *testing.T, srv http.Handler, email, password string) *httptest.ResponseRecorder {
	t.Helper()
	tok := csrfCookie(t, srv)
	form := url.Values{"email": {email}, "password": {password}, csrf.FormField: {tok.Value}}
	return submitForm(srv, "/login", form, []*http.Cookie{tok}, "")
}

// postTOTP submits a code against the pending challenge cookie.
// in: t, handler, cookie, code, remote addr. out: recorder.
func postTOTP(t *testing.T, srv http.Handler, pending *http.Cookie, code, remote string) *httptest.ResponseRecorder {
	t.Helper()
	tok := csrfCookie(t, srv)
	form := url.Values{"code": {code}, csrf.FormField: {tok.Value}}
	return submitForm(srv, "/login/totp", form, []*http.Cookie{tok, pending}, remote)
}

// postAuthed submits a settings form with the session and a CSRF token.
// in: t, handler, path, form, session cookie, remote addr, extra cookies. out: recorder.
func postAuthed(t *testing.T, srv http.Handler, path string, form url.Values, session *http.Cookie, remote string, extra ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	tok := csrfCookie(t, srv)
	form.Set(csrf.FormField, tok.Value)
	cookies := append([]*http.Cookie{tok, session}, extra...)
	return submitForm(srv, path, form, cookies, remote)
}

// submitForm sends one urlencoded POST.
// in: handler, path, form, cookies, remote addr. out: recorder.
func submitForm(srv http.Handler, path string, form url.Values, cookies []*http.Cookie, remote string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if remote != "" {
		req.RemoteAddr = remote
	}
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// cookieNamed returns the non-empty cookie set on rec.
// in: t, recorder, name. out: cookie.
func cookieNamed(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name && c.Value != "" {
			return c
		}
	}
	t.Fatalf("cookie %s missing", name)
	return nil
}
