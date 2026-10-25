//go:build integration

package web

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/ws"
)

// adminMqttShell is a super-admin session against the shell handler. done
// closes when the handler returns, which is after its tap cleanup.
type adminMqttShell struct {
	env     *servicetest.Env
	s       *Server
	adminID uuid.UUID
	dial    func() (*websocket.Conn, error)
	done    chan struct{}
}

func startAdminMqttShell(t *testing.T, home string) *adminMqttShell {
	t.Helper()
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	env.SeedTenant(t, home)
	admin, err := env.Services.Auth.CreateUser(home, "root@"+home+".test", "Root", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.Super.Exec(context.Background(), `UPDATE users SET is_super_admin = true WHERE id = $1`, admin.ID); err != nil {
		t.Fatal(err)
	}
	tok, _, err := env.Services.Auth.CreateSession(home, admin.ID, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{}, 8)
	h := func(w http.ResponseWriter, r *http.Request) {
		s.handleAdminMqttWS(w, r)
		done <- struct{}{}
	}
	srv := httptest.NewServer(authmw.Middleware(env.Services.Auth, nil)(authmw.RequireSuperAdmin(h)))
	t.Cleanup(srv.Close)
	dial := func() (*websocket.Conn, error) {
		c, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"),
			http.Header{"Cookie": {authmw.CookieName + "=" + tok}})
		if resp != nil {
			_ = resp.Body.Close()
		}
		return c, err
	}
	return &adminMqttShell{env: env, s: s, adminID: admin.ID, dial: dial, done: done}
}

// The admin MQTT shell ends with ws.ReauthCloseCode after ws.MaxLifetime, and
// the reconnect re-checks super-admin, so a demoted admin loses the shell.
func TestAdminMqttShell_EndsAtMaxLifetime(t *testing.T) {
	old := ws.MaxLifetime
	ws.MaxLifetime = 500 * time.Millisecond
	t.Cleanup(func() { ws.MaxLifetime = old })

	sh := startAdminMqttShell(t, "life-home")
	c, err := sh.dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		_, _, err := c.ReadMessage()
		var ce *websocket.CloseError
		if errors.As(err, &ce) {
			if ce.Code != ws.ReauthCloseCode {
				t.Fatalf("close code = %d, want %d", ce.Code, ws.ReauthCloseCode)
			}
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}

	if _, err := sh.env.Super.Exec(context.Background(), `UPDATE users SET is_super_admin = false WHERE id = $1`, sh.adminID); err != nil {
		t.Fatal(err)
	}
	if rc, err := sh.dial(); err == nil {
		_ = rc.Close()
		t.Fatal("reconnect after demotion was accepted")
	}
}

// When the writer gives up (here a stalled client trips its write deadline),
// a reader blocked on a full outbound queue must still return, so the
// handler's deferred tap cleanup runs.
func TestAdminMqttShell_WriterExitReleasesReader(t *testing.T) {
	sh := startAdminMqttShell(t, "stall-home")
	c, err := sh.dial()
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.WriteJSON(adminMqttInboundMsg{Type: "subscribe", Pattern: "thesada/stall/#"}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	for {
		var m adminMqttOutboundMsg
		if err := c.ReadJSON(&m); err != nil {
			t.Fatalf("waiting for subscribe ack: %v", err)
		}
		if m.Type == "info" && strings.HasPrefix(m.Info, "subscribed:") {
			break
		}
	}

	// Stop reading. Big payloads stall the writer in a socket write, then
	// fill the outbound queue behind it.
	payload := []byte(strings.Repeat("x", 64<<10))
	for i := 0; i < 2*adminMqttMaxBuffer; i++ {
		if err := sh.s.mqtt.PublishRaw("thesada/stall/x", payload, 0, false); err != nil {
			t.Fatal(err)
		}
	}
	// The reply to this frame has no room in the queue.
	if err := c.WriteJSON(adminMqttInboundMsg{Type: "bogus"}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-sh.done:
	case <-time.After(20 * time.Second):
		t.Fatal("handler still running after the writer exited: reader blocked, tap never removed")
	}
}
