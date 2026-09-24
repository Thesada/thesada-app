// Package notify sends the login and password-reset emails shared by the
// web dashboard and the JSON API. One template set, one rate limit.
package notify

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/ratelimit"
	"thesada.app/app/pkg/service"
)

const (
	maxPerIP = 5
	// Address-wide ceiling. Above one client's budget so that client cannot
	// spend the address on its own. Distributed sends still stop here.
	maxPerEmail = maxPerIP * 4
	window      = time.Hour
)

//go:embed templates
var templatesFS embed.FS

// Accounts is the slice of AuthService the mail path needs.
type Accounts interface {
	GetUserByEmailAnyTenant(email string) (*service.User, error)
	CreateMagicLink(userID uuid.UUID) (string, time.Time, error)
	CreateResetLink(userID uuid.UUID) (string, time.Time, error)
}

// MIMESender delivers a multipart text+html message.
type MIMESender interface {
	SendMIME(to, subject, text, html string) error
}

// Mail renders the shared email templates and enforces the per-client
// and per-address send caps.
type Mail struct {
	accounts  Accounts
	send      MIMESender
	baseURL   string
	emailHTML map[string]*template.Template
	emailText map[string]*texttemplate.Template
	byEmail   *ratelimit.Limiter
	byIP      *ratelimit.Limiter
}

// New loads the email templates and starts the limiter sweepers.
// in: accounts, sender, public base URL. out: ready *Mail.
func New(accounts Accounts, send MIMESender, baseURL string) *Mail {
	m := &Mail{
		accounts: accounts,
		send:     send,
		baseURL:  strings.TrimRight(baseURL, "/"),
		byEmail:  ratelimit.New(window, maxPerEmail),
		byIP:     ratelimit.New(window, maxPerIP),
	}
	names := []string{"login_link", "reset_link"}
	m.emailText = make(map[string]*texttemplate.Template, len(names))
	m.emailHTML = make(map[string]*template.Template, len(names))
	for _, name := range names {
		m.emailText[name] = texttemplate.Must(texttemplate.ParseFS(templatesFS, "templates/"+name+".txt"))
		m.emailHTML[name] = template.Must(template.ParseFS(templatesFS, "templates/"+name+".html"))
	}
	m.byEmail.StartSweeper(context.Background())
	m.byIP.StartSweeper(context.Background())
	return m
}

// RequestLoginLink emails a one-time sign-in link. Unknown addresses and
// rate-limit hits return nil so the caller can answer "sent" either way.
// in: email, client ip. out: error only when a real account could not be read or the token could not be stored.
func (m *Mail) RequestLoginLink(email, ip string) error {
	return m.request(email, ip, "login_link", "Your thesada sign-in link", "/login/verify?token=", true)
}

// RequestResetLink emails a password-reset link. Same silence rules as RequestLoginLink.
// in: email, client ip. out: error only on an unexpected account or token failure.
func (m *Mail) RequestResetLink(email, ip string) error {
	return m.request(email, ip, "reset_link", "Your thesada password reset link", "/reset-password?token=", false)
}

// SendResetLink emails a reset link that the caller already created.
// in: recipient, absolute link. out: render or send error.
func (m *Mail) SendResetLink(to, link string) error {
	return m.sendTemplate(to, "Your thesada password reset link", "reset_link", link)
}

func (m *Mail) request(email, ip, tmpl, subject, path string, login bool) error {
	if !m.allow(email, ip) {
		return nil
	}
	u, err := m.accounts.GetUserByEmailAnyTenant(email)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			return nil
		}
		return err
	}
	var token string
	if login {
		token, _, err = m.accounts.CreateMagicLink(u.ID)
	} else {
		token, _, err = m.accounts.CreateResetLink(u.ID)
	}
	if err != nil {
		return err
	}
	if err := m.sendTemplate(u.Email, subject, tmpl, m.baseURL+path+token); err != nil {
		slog.Error("notify send failed", "template", tmpl, "err", err)
	}
	return nil
}

// The IP cap is checked first so a client already over quota does not create
// an address key. The IP hit is recorded only after the address cap accepts.
func (m *Mail) allow(email, ip string) bool {
	email = strings.ToLower(email)
	if ip != "" && !m.byIP.WouldAllow("ip:"+ip) {
		slog.Warn("notify ip rate-limited", "ip", ip)
		return false
	}
	if !m.byEmail.Allow("email:" + email) {
		slog.Warn("notify email rate-limited", "email", email)
		return false
	}
	if ip != "" && !m.byIP.Allow("ip:"+ip) {
		slog.Warn("notify ip rate-limited", "ip", ip)
		return false
	}
	return true
}

func (m *Mail) sendTemplate(to, subject, name, link string) error {
	textBody, htmlBody, err := m.render(name, map[string]interface{}{"Link": link})
	if err != nil {
		return err
	}
	return m.send.SendMIME(to, subject, textBody, htmlBody)
}

func (m *Mail) render(name string, data interface{}) (string, string, error) {
	tt, ok := m.emailText[name]
	if !ok {
		return "", "", errors.New("email text template not found: " + name)
	}
	ht, ok := m.emailHTML[name]
	if !ok {
		return "", "", errors.New("email html template not found: " + name)
	}
	var textBuf, htmlBuf bytes.Buffer
	if err := tt.Execute(&textBuf, data); err != nil {
		return "", "", err
	}
	if err := ht.Execute(&htmlBuf, data); err != nil {
		return "", "", err
	}
	return textBuf.String(), htmlBuf.String(), nil
}
