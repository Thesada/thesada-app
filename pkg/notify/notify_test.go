package notify

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
)

type fakeAccounts struct {
	user   *service.User
	err    error
	logins int
}

func (f *fakeAccounts) GetUserByEmailAnyTenant(string) (*service.User, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.user, nil
}

func (f *fakeAccounts) CreateMagicLink(uuid.UUID) (string, time.Time, error) {
	f.logins++
	return "login-token", time.Now(), nil
}

func (f *fakeAccounts) CreateResetLink(uuid.UUID) (string, time.Time, error) {
	return "reset-token", time.Now(), nil
}

type fakeMail struct {
	to, subject, text, html string
	sends                   int
}

func (f *fakeMail) SendMIME(to, subject, text, html string) error {
	f.sends++
	f.to, f.subject, f.text, f.html = to, subject, text, html
	return nil
}

func TestRequestLoginLink_UnknownAddressSendsNothing(t *testing.T) {
	mail := &fakeMail{}
	m := New(&fakeAccounts{err: service.ErrNotFound}, mail, "https://app.example")
	if err := m.RequestLoginLink("nobody@example.com", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if mail.sends != 0 {
		t.Fatalf("sends = %d, want 0", mail.sends)
	}
}

func TestRequestLoginLink_SendsOneLink(t *testing.T) {
	id := uuid.New()
	mail := &fakeMail{}
	accounts := &fakeAccounts{user: &service.User{ID: id, Email: "ada@example.com"}}
	m := New(accounts, mail, "https://app.example/")
	if err := m.RequestLoginLink("Ada@example.com", "192.0.2.1"); err != nil {
		t.Fatal(err)
	}
	if mail.sends != 1 || mail.to != "ada@example.com" {
		t.Fatalf("send to %q count %d", mail.to, mail.sends)
	}
	if !strings.Contains(mail.text, "https://app.example/login/verify?token=login-token") {
		t.Fatalf("text missing link: %s", mail.text)
	}
	if !strings.Contains(mail.html, "https://app.example/login/verify?token=login-token") {
		t.Fatalf("html missing link: %s", mail.html)
	}
}

func TestRequestLoginLink_RateLimitIsSilent(t *testing.T) {
	mail := &fakeMail{}
	accounts := &fakeAccounts{user: &service.User{ID: uuid.New(), Email: "ada@example.com"}}
	m := New(accounts, mail, "https://app.example")
	for i := 0; i < maxPerIP+2; i++ {
		if err := m.RequestLoginLink("ada@example.com", "192.0.2.9"); err != nil {
			t.Fatal(err)
		}
	}
	if mail.sends != maxPerIP {
		t.Fatalf("sends = %d, want %d", mail.sends, maxPerIP)
	}
}

func TestRequestLoginLink_OtherClientStillSends(t *testing.T) {
	mail := &fakeMail{}
	accounts := &fakeAccounts{user: &service.User{ID: uuid.New(), Email: "ada@example.com"}}
	m := New(accounts, mail, "https://app.example")
	for i := 0; i < maxPerIP; i++ {
		if err := m.RequestLoginLink("ada@example.com", "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.RequestLoginLink("ada@example.com", "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	if mail.sends != maxPerIP+1 {
		t.Fatalf("sends = %d, want %d", mail.sends, maxPerIP+1)
	}
}

func TestRequestLoginLink_OverQuotaClientDoesNotSpendOtherAddresses(t *testing.T) {
	mail := &fakeMail{}
	accounts := &fakeAccounts{user: &service.User{ID: uuid.New(), Email: "ada@example.com"}}
	m := New(accounts, mail, "https://app.example")
	for i := 0; i < maxPerIP; i++ {
		if err := m.RequestLoginLink("ada@example.com", "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < maxPerEmail+2; i++ {
		if err := m.RequestLoginLink("other@example.com", "192.0.2.1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.RequestLoginLink("other@example.com", "192.0.2.2"); err != nil {
		t.Fatal(err)
	}
	if mail.sends != maxPerIP+1 {
		t.Fatalf("sends = %d, want %d", mail.sends, maxPerIP+1)
	}
}

func TestRequestLoginLink_AddressCapStopsDistributedSends(t *testing.T) {
	mail := &fakeMail{}
	accounts := &fakeAccounts{user: &service.User{ID: uuid.New(), Email: "ada@example.com"}}
	m := New(accounts, mail, "https://app.example")
	clients := maxPerEmail / maxPerIP
	for n := 0; n < clients; n++ {
		ip := fmt.Sprintf("192.0.2.%d", n+1)
		for i := 0; i < maxPerIP; i++ {
			if err := m.RequestLoginLink("ada@example.com", ip); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := m.RequestLoginLink("ada@example.com", "198.51.100.1"); err != nil {
		t.Fatal(err)
	}
	if mail.sends != maxPerEmail {
		t.Fatalf("sends = %d, want %d", mail.sends, maxPerEmail)
	}
}

func TestRequestLoginLink_AddressCapDoesNotSpendClientBudget(t *testing.T) {
	mail := &fakeMail{}
	accounts := &fakeAccounts{user: &service.User{ID: uuid.New(), Email: "ada@example.com"}}
	m := New(accounts, mail, "https://app.example")
	clients := maxPerEmail / maxPerIP
	for n := 0; n < clients; n++ {
		ip := fmt.Sprintf("192.0.2.%d", n+1)
		for i := 0; i < maxPerIP; i++ {
			if err := m.RequestLoginLink("ada@example.com", ip); err != nil {
				t.Fatal(err)
			}
		}
	}
	for i := 0; i < maxPerIP; i++ {
		if err := m.RequestLoginLink("ada@example.com", "198.51.100.9"); err != nil {
			t.Fatal(err)
		}
	}
	if err := m.RequestLoginLink("other@example.com", "198.51.100.9"); err != nil {
		t.Fatal(err)
	}
	if mail.sends != maxPerEmail+1 {
		t.Fatalf("sends = %d, want %d", mail.sends, maxPerEmail+1)
	}
}
