package ws

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/service"
)

// oneSession accepts exactly one token.
type oneSession struct{}

func (oneSession) ValidateSession(token string) (*service.Session, error) {
	if token != "good" {
		return nil, service.ErrNotFound
	}
	return &service.Session{User: &service.User{Email: "u@ws.test", TenantID: "t1"}}, nil
}

// A connection ends with ReauthCloseCode after MaxLifetime, so the browser
// reconnects through the auth middleware instead of streaming forever.
func TestConnectionEndsAtMaxLifetime(t *testing.T) {
	old := MaxLifetime
	MaxLifetime = 300 * time.Millisecond
	t.Cleanup(func() { MaxLifetime = old })

	hub := New(&config.Config{BaseURL: "http://localhost"})
	srv := httptest.NewServer(authmw.Middleware(oneSession{}, nil)(authmw.RequireAuth(hub.ServeHTTP)))
	t.Cleanup(srv.Close)

	h := http.Header{"Cookie": {authmw.CookieName + "=good"}}
	c, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), h)
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()

	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	for {
		_, _, err := c.ReadMessage()
		var ce *websocket.CloseError
		if errors.As(err, &ce) {
			if ce.Code != ReauthCloseCode {
				t.Fatalf("close code = %d, want %d", ce.Code, ReauthCloseCode)
			}
			if time.Since(start) > 3*time.Second {
				t.Fatalf("closed after %v, want about MaxLifetime", time.Since(start))
			}
			return
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
}
