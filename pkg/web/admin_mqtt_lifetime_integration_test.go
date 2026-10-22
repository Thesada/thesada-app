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

	"github.com/gorilla/websocket"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/ws"
)

// The admin MQTT shell ends with ws.ReauthCloseCode after ws.MaxLifetime, so
// a demoted admin cannot keep an open shell past it.
func TestAdminMqttShell_EndsAtMaxLifetime(t *testing.T) {
	old := ws.MaxLifetime
	ws.MaxLifetime = 500 * time.Millisecond
	t.Cleanup(func() { ws.MaxLifetime = old })

	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	ctx := context.Background()
	const home = "life-home"
	env.SeedTenant(t, home)
	admin, err := env.Services.Auth.CreateUser(home, "root@life.test", "Root", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.Super.Exec(ctx, `UPDATE users SET is_super_admin = true WHERE id = $1`, admin.ID); err != nil {
		t.Fatal(err)
	}
	tok, _, err := env.Services.Auth.CreateSession(home, admin.ID, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(authmw.Middleware(env.Services.Auth, nil)(authmw.RequireSuperAdmin(s.handleAdminMqttWS)))
	t.Cleanup(srv.Close)

	c, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"),
		http.Header{"Cookie": {authmw.CookieName + "=" + tok}})
	if resp != nil {
		_ = resp.Body.Close()
	}
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
			return
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
}
