// Package mailer sends transactional email via plain SMTP with STARTTLS.
// Supports plain-text (Send) and multipart/alternative text+html (SendMIME).
package mailer

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/smtp"
	"strings"
	"time"

	"thesada.app/app/pkg/config"
)

// sendTimeout bounds one whole SMTP session: dial, handshake and DATA.
const sendTimeout = 30 * time.Second

// Mailer holds SMTP connection config. Safe for concurrent use (each send
// opens a fresh connection).
type Mailer struct {
	host    string
	port    string
	user    string
	pass    string
	from    string
	timeout time.Duration
}

// New constructs a Mailer from the application config.
// in: cfg. out: *Mailer (no connection attempted until Send).
func New(cfg *config.Config) *Mailer {
	return &Mailer{
		host:    cfg.SMTPHost,
		port:    cfg.SMTPPort,
		user:    cfg.SMTPUsername,
		pass:    cfg.SMTPPassword,
		from:    cfg.SMTPFrom,
		timeout: sendTimeout,
	}
}

// Send delivers a plain-text email to one recipient.
// No-op with a warning log if SMTPHost is empty.
// in: to address, subject, body. out: error from the SMTP session.
func (m *Mailer) Send(to, subject, body string) error {
	if m.host == "" {
		slog.Warn("mailer disabled (SMTPHost empty), dropping message", "to", to, "subject", subject)
		return nil
	}
	to, subject = sanitizeHeader(to), sanitizeHeader(subject)
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		m.from, to, subject, body)
	return m.sendMail(to, []byte(msg))
}

// sendMail is smtp.SendMail with a dial timeout and one deadline over the
// session, so a stalled server fails the send instead of hanging it.
// in: recipient, raw message. out: error.
func (m *Mailer) sendMail(to string, msg []byte) error {
	conn, err := (&net.Dialer{Timeout: m.timeout}).Dial("tcp", net.JoinHostPort(m.host, m.port))
	if err != nil {
		return fmt.Errorf("smtp dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(m.timeout)); err != nil {
		return fmt.Errorf("smtp deadline: %w", err)
	}
	c, err := smtp.NewClient(conn, m.host)
	if err != nil {
		return fmt.Errorf("smtp greeting: %w", err)
	}
	defer func() { _ = c.Close() }()
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}); err != nil {
			return fmt.Errorf("smtp starttls: %w", err)
		}
	}
	if ok, _ := c.Extension("AUTH"); !ok {
		return errors.New("smtp: server doesn't support AUTH")
	}
	if err := c.Auth(smtp.PlainAuth("", m.user, m.pass, m.host)); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	if err := c.Mail(m.from); err != nil {
		return err
	}
	if err := c.Rcpt(to); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(msg); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// sanitizeHeader strips CR and LF from a value placed into an email header
// so a hostile recipient address or subject cannot inject extra headers or a
// message body (CRLF / header injection). Go's net/smtp already rejects
// newlines in the SMTP envelope; this guards the headers we build by hand.
// in: raw header value. out: value with all \r and \n removed.
func sanitizeHeader(v string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(v)
}

// randomBoundary returns a hex boundary string for multipart/alternative.
// 16 bytes of entropy is plenty for a MIME boundary marker. A crypto/rand
// failure is near-impossible and the boundary need not be secret, only
// unlikely to collide with the body, so we log and fall back rather than
// fail the send.
// in: none. out: boundary marker string.
func randomBoundary() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		slog.Warn("mailer: rand.Read failed building MIME boundary", "err", err)
	}
	return "thesada_" + hex.EncodeToString(b[:])
}

// SendMIME delivers a multipart/alternative email with both text and HTML
// bodies. Mail clients that don't render HTML get the text variant; modern
// clients show the HTML. If html is empty the call falls back to Send.
// in: to address, subject, plain text body, html body. out: error.
func (m *Mailer) SendMIME(to, subject, textBody, htmlBody string) error {
	if m.host == "" {
		slog.Warn("mailer disabled (SMTPHost empty), dropping message", "to", to, "subject", subject)
		return nil
	}
	if htmlBody == "" {
		return m.Send(to, subject, textBody)
	}
	to, subject = sanitizeHeader(to), sanitizeHeader(subject)
	boundary := randomBoundary()
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", m.from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", subject)
	b.WriteString("MIME-Version: 1.0\r\n")
	fmt.Fprintf(&b, "Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary)
	// Text part first per RFC 2046 - clients pick the last part they can
	// render, and HTML ranks higher than plain.
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(textBody)
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "--%s\r\n", boundary)
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(htmlBody)
	b.WriteString("\r\n")
	fmt.Fprintf(&b, "--%s--\r\n", boundary)
	return m.sendMail(to, []byte(b.String()))
}
