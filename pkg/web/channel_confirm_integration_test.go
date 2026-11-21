//go:build integration

// Email channel confirm links: a GET (what a mail scanner does) changes
// nothing, the POST confirms once, and confirm mails are capped per user.
//
//	go test -tags integration -run TestChannelConfirmWeb ./pkg/web/...
package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/csrf"
	"thesada.app/app/pkg/notify"
	"thesada.app/app/pkg/service/servicetest"
)

type confirmMails struct {
	mu   sync.Mutex
	to   []string
	text []string
}

func (m *confirmMails) SendMIME(to, _, text, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.to = append(m.to, to)
	m.text = append(m.text, text)
	return nil
}

func (m *confirmMails) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.to)
}

var confirmLink = regexp.MustCompile(`https://app\.example/alerts/channels/confirm\?token=([A-Za-z0-9_-]+)`)

// lastToken is the token in the newest confirm mail.
func (m *confirmMails) lastToken(t *testing.T) string {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.text) == 0 {
		t.Fatal("no confirm mail sent")
	}
	g := confirmLink.FindStringSubmatch(m.text[len(m.text)-1])
	if g == nil {
		t.Fatalf("confirm mail has no link: %s", m.text[len(m.text)-1])
	}
	return g[1]
}

type confirmWeb struct {
	env   *servicetest.Env
	srv   *Server
	mails *confirmMails
}

func startConfirmWeb(t *testing.T) confirmWeb {
	t.Helper()
	env := servicetest.Start(t)
	mails := &confirmMails{}
	notes := notify.New(env.Services.Auth, mails, "https://app.example")
	return confirmWeb{env: env, srv: New(env.Cfg, env.Services, nil, nil, nil, notes), mails: mails}
}

// session seeds a user in tenant and signs them in. out: user id, session cookie.
func (c confirmWeb) session(t *testing.T, tenant, email string) (uuid.UUID, *http.Cookie) {
	t.Helper()
	c.env.SeedTenant(t, tenant)
	uid := mustWebUser(t, c.env, tenant, email, "")
	tok, _, err := c.env.Services.Auth.CreateSession(tenant, uid, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	return uid, &http.Cookie{Name: authmw.CookieName, Value: tok}
}

// addEmailChannel adds one through the settings form. out: channel id, redirect.
func (c confirmWeb) addEmailChannel(t *testing.T, uid uuid.UUID, session *http.Cookie, target string) (uuid.UUID, string) {
	t.Helper()
	rec := postAuthed(t, c.srv, "/settings/channels/add", url.Values{"kind": {"email"}, "target": {target}}, session, "")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("add = %d %s", rec.Code, rec.Body.String())
	}
	var id uuid.UUID
	if err := c.env.Super.QueryRow(context.Background(),
		`SELECT id FROM notification_channels WHERE user_id = $1 AND target = $2`, uid, target).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id, rec.Header().Get("Location")
}

func (c confirmWeb) confirmed(t *testing.T, id uuid.UUID) bool {
	t.Helper()
	var ok bool
	if err := c.env.Super.QueryRow(context.Background(),
		`SELECT confirmed_at IS NOT NULL FROM notification_channels WHERE id = $1`, id).Scan(&ok); err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestChannelConfirmWeb_GetChangesNothingPostConfirmsOnce(t *testing.T) {
	c := startConfirmWeb(t)
	uid, session := c.session(t, "cc-web", "owner@cc.test")
	id, loc := c.addEmailChannel(t, uid, session, "friend@elsewhere.test")
	if !strings.Contains(loc, "confirm=sent") {
		t.Fatalf("add redirect = %q, want confirm=sent", loc)
	}
	if c.mails.count() != 1 || c.mails.to[0] != "friend@elsewhere.test" {
		t.Fatalf("mails to %v, want one to friend@elsewhere.test", c.mails.to)
	}
	token := c.mails.lastToken(t)

	var form url.Values
	var csrfTok *http.Cookie
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		c.srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/alerts/channels/confirm?token="+url.QueryEscape(token), nil))
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `action="/alerts/channels/confirm"`) {
			t.Fatalf("GET = %d, want the confirm form", rec.Code)
		}
		if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
			t.Fatalf("Referrer-Policy = %q, want no-referrer", got)
		}
		form, csrfTok = hiddenFields(rec.Body.String()), cookieNamed(t, rec, csrf.CookieName)
	}
	if c.confirmed(t, id) {
		t.Fatal("a GET confirmed the channel")
	}
	if form.Get("token") != token {
		t.Fatalf("form token = %q, want the link token", form.Get("token"))
	}

	post := func() string {
		return submitForm(c.srv, "/alerts/channels/confirm", form, []*http.Cookie{csrfTok}, "").Body.String()
	}
	if body := post(); !strings.Contains(body, "Confirmed.") {
		t.Fatalf("POST body lacks the confirmed text: %s", body)
	}
	if !c.confirmed(t, id) {
		t.Fatal("POST did not confirm the channel")
	}
	if body := post(); !strings.Contains(body, "This link is not valid.") {
		t.Fatal("second POST did not show the not-valid page")
	}
}

func TestChannelConfirmWeb_BadTokenPage(t *testing.T) {
	c := startConfirmWeb(t)
	for _, path := range []string{"/alerts/channels/confirm?token=nope", "/alerts/channels/confirm"} {
		rec := httptest.NewRecorder()
		c.srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		body := rec.Body.String()
		if !strings.Contains(body, "This link is not valid.") || strings.Contains(body, `action="/alerts/channels/confirm"`) {
			t.Fatalf("GET %s = %d, want the not-valid page without a form", path, rec.Code)
		}
	}
	tok := csrfCookie(t, c.srv)
	form := url.Values{"token": {"nope"}, csrf.FormField: {tok.Value}}
	if body := submitForm(c.srv, "/alerts/channels/confirm", form, []*http.Cookie{tok}, "").Body.String(); !strings.Contains(body, "This link is not valid.") {
		t.Fatal("POST with a bad token did not show the not-valid page")
	}
}

func TestChannelConfirmWeb_ResendIsCappedAndOwnerOnly(t *testing.T) {
	c := startConfirmWeb(t)
	uid, session := c.session(t, "cc-cap", "owner@cap.test")
	_, outsider := c.session(t, "cc-other", "outsider@other.test")
	id, _ := c.addEmailChannel(t, uid, session, "friend@cap.test")

	page := getAs(c.srv, "/settings", session).Body.String()
	if !strings.Contains(page, "waiting for confirmation") || !strings.Contains(page, "/settings/channels/"+id.String()+"/resend") {
		t.Fatal("settings page shows no waiting state or resend button")
	}

	resend := func(s *http.Cookie) *httptest.ResponseRecorder {
		return postAuthed(t, c.srv, "/settings/channels/"+id.String()+"/resend", url.Values{}, s, "")
	}
	if rec := resend(outsider); rec.Code != http.StatusNotFound {
		t.Fatalf("outsider resend = %d, want 404", rec.Code)
	}
	for i := 0; i < 2; i++ {
		if loc := resend(session).Header().Get("Location"); !strings.Contains(loc, "confirm=sent") {
			t.Fatalf("resend %d redirect = %q, want confirm=sent", i+1, loc)
		}
	}
	if c.mails.count() != channelConfirmMax {
		t.Fatalf("mails = %d, want %d", c.mails.count(), channelConfirmMax)
	}
	live := c.mails.lastToken(t)
	loc := resend(session).Header().Get("Location")
	if !strings.Contains(loc, "confirm=later") {
		t.Fatalf("4th mail redirect = %q, want confirm=later", loc)
	}
	if c.mails.count() != channelConfirmMax {
		t.Fatalf("4th mail in the hour was sent: %d mails", c.mails.count())
	}
	if page := getAs(c.srv, strings.TrimSuffix(loc, "#notifications"), session).Body.String(); !strings.Contains(page, "try Resend later") {
		t.Fatal("settings page does not say to resend later")
	}
	if err := c.env.Services.Alerts.ConfirmChannel(context.Background(), live); err != nil {
		t.Fatalf("the last mailed link died on the capped resend: %v", err)
	}
}
