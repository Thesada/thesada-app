package web

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/notify"
	"thesada.app/app/pkg/service"
)

type linkAccounts struct{}

func (linkAccounts) GetUserByEmailAnyTenant(email string) (*service.User, error) {
	switch email {
	case "known@example.com":
		return &service.User{ID: uuid.New(), Email: email}, nil
	case "broken@example.com":
		return nil, errors.New("db down")
	}
	return nil, service.ErrNotFound
}

func (linkAccounts) CreateMagicLink(uuid.UUID) (string, time.Time, error) {
	return "login-tok", time.Now(), nil
}

func (linkAccounts) CreateResetLink(uuid.UUID) (string, time.Time, error) {
	return "reset-tok", time.Now(), nil
}

// stallSender blocks every send until release closes, like a stalled SMTP
// server. entered carries each message's text body.
type stallSender struct {
	entered chan string
	release chan struct{}
}

func (s stallSender) SendMIME(_, _, text, _ string) error {
	s.entered <- text
	<-s.release
	return nil
}

var renderedNow = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2} \S+`)

// The login and forgot forms answer a known, an unknown and a failing address
// with one page and without waiting on the mail server.
func TestLinkForms_SamePageNoWaitOnSend(t *testing.T) {
	sender := stallSender{entered: make(chan string, 4), release: make(chan struct{})}
	t.Cleanup(func() { close(sender.release) })
	s := &Server{cfg: &config.Config{}, notes: notify.New(linkAccounts{}, sender, "https://app.example")}
	s.parseTemplates()

	for i, form := range []struct {
		path    string
		handler http.HandlerFunc
		link    string
	}{{"/login", s.handleLoginSubmit, "/login/verify?token=login-tok"},
		{"/forgot", s.handleForgotSubmit, "/reset-password?token=reset-tok"}} {
		emails := []string{"known@example.com", "nobody@example.com", "broken@example.com"}
		pages := make([]string, 0, len(emails))
		for _, email := range emails {
			req := httptest.NewRequest(http.MethodPost, form.path, strings.NewReader(url.Values{"email": {email}}.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.RemoteAddr = "192.0.2." + string(rune('1'+i)) + ":1234"
			rec := httptest.NewRecorder()
			done := make(chan struct{})
			go func() { form.handler(rec, req); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatalf("%s %s waited on the stalled send", form.path, email)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("%s %s = %d, want 200", form.path, email, rec.Code)
			}
			body := strings.ReplaceAll(rec.Body.String(), email, "EMAIL")
			pages = append(pages, renderedNow.ReplaceAllString(body, "NOW"))
		}
		if pages[0] != pages[1] || pages[0] != pages[2] {
			t.Fatalf("%s: known, unknown and failing addresses render different pages", form.path)
		}
		select {
		case text := <-sender.entered:
			if !strings.Contains(text, form.link) {
				t.Fatalf("%s: mail does not carry %s:\n%s", form.path, form.link, text)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: the known address never reached the sender", form.path)
		}
	}
}
