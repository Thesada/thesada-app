//go:build integration

// The admin MQTT shell over a real WebSocket, broker and DB: origin check,
// the topic-root guard, the publish rate limit, and the one audit row per
// session (topics and sizes, never payloads).
//
//	go test -tags integration -run TestAdminMqttShell ./pkg/web/...
package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
)

const shellCanary = "PAYLOAD-CANARY-9d1"

func TestAdminMqttShell(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	ctx := context.Background()

	const home = "shell-home"
	env.SeedTenant(t, home)
	admin, err := env.Services.Auth.CreateUser(home, "root@shell.test", "Root", false)
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
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")

	// dial returns the conn and the handshake status; the body is closed here.
	dial := func(origin string) (*websocket.Conn, int, error) {
		h := http.Header{}
		h.Set("Cookie", authmw.CookieName+"="+tok)
		if origin != "" {
			h.Set("Origin", origin)
		}
		c, resp, err := websocket.DefaultDialer.Dial(wsURL, h)
		code := 0
		if resp != nil {
			code = resp.StatusCode
			_ = resp.Body.Close()
		}
		return c, code, err
	}
	// await reads frames until one matches, skipping tap traffic.
	await := func(t *testing.T, c *websocket.Conn, typ, contains string) {
		t.Helper()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		for {
			var m adminMqttOutboundMsg
			if err := c.ReadJSON(&m); err != nil {
				t.Fatalf("waiting for %s %q: %v", typ, contains, err)
			}
			if m.Type == typ && strings.Contains(m.Error+m.Info, contains) {
				return
			}
		}
	}
	// auditAfter waits for the session's row, written after close.
	auditAfter := func(t *testing.T, action string, since int64) map[string]any {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			var raw []byte
			err := env.Super.QueryRow(ctx,
				`SELECT detail FROM admin_audit WHERE action = $1 AND id > $2 ORDER BY id DESC LIMIT 1`,
				action, since).Scan(&raw)
			if err == nil {
				var d map[string]any
				if err := json.Unmarshal(raw, &d); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), shellCanary) {
					t.Fatal("audit detail carries a payload")
				}
				return d
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("no %s audit row after close", action)
		return nil
	}
	maxID := func() int64 {
		var id int64
		_ = env.Super.QueryRow(ctx, `SELECT coalesce(max(id), 0) FROM admin_audit`).Scan(&id)
		return id
	}

	t.Run("foreign origin is refused", func(t *testing.T) {
		c, code, err := dial("https://evil.example")
		if err == nil {
			_ = c.Close()
			t.Fatal("upgrade from a foreign origin succeeded")
		}
		if code != http.StatusForbidden {
			t.Fatalf("foreign origin status = %d, want 403", code)
		}
	})

	t.Run("missing origin is allowed", func(t *testing.T) {
		// Deliberate (non-browser clients send none; the session cookie is
		// the gate). Pinned so a change is a decision, not an accident.
		c, _, err := dial("")
		if err != nil {
			t.Fatalf("upgrade without origin: %v", err)
		}
		_ = c.Close()
	})

	t.Run("guard, rate limit and audit", func(t *testing.T) {
		var mu sync.Mutex
		seen := 0
		cancel, err := s.mqtt.RegisterTap("thesada/shell/#", func(topic string, payload []byte, _ bool, _ byte) {
			if string(payload) == shellCanary {
				mu.Lock()
				seen++
				mu.Unlock()
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		defer cancel()

		since := maxID()
		c, _, err := dial(s.cfg.BaseURL)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		pub := func(topic string) {
			if err := c.WriteJSON(adminMqttInboundMsg{Type: "publish", Topic: topic, Payload: shellCanary}); err != nil {
				t.Fatal(err)
			}
		}

		pub("elsewhere/x")
		await(t, c, "error", "topic must start with thesada/")

		for i := 0; i < adminMqttPublishMax+5; i++ {
			pub("thesada/shell/dev/cli/x")
		}
		await(t, c, "error", "rate limit")

		if err := c.WriteJSON(adminMqttInboundMsg{Type: "subscribe", Pattern: "thesada/shell/#"}); err != nil {
			t.Fatal(err)
		}
		await(t, c, "info", "subscribed: thesada/shell/#")
		_ = c.Close()

		d := auditAfter(t, "mqtt.shell_publish", since)
		if d["publishes"] != float64(adminMqttPublishMax) {
			t.Fatalf("publishes = %v, want %d (the rest were rate limited)", d["publishes"], adminMqttPublishMax)
		}
		published, _ := d["published"].([]any)
		if len(published) != adminMqttPublishMax {
			t.Fatalf("published = %d entries, want %d", len(published), adminMqttPublishMax)
		}
		first, _ := published[0].(map[string]any)
		if first["topic"] != "thesada/shell/dev/cli/x" || first["bytes"] != float64(len(shellCanary)) {
			t.Fatalf("published[0] = %v", first)
		}
		if subs, _ := d["subscribed"].([]any); len(subs) != 1 || subs[0] != "thesada/shell/#" {
			t.Fatalf("subscribed = %v", d["subscribed"])
		}
		got := 0
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			mu.Lock()
			got = seen
			mu.Unlock()
			if got >= adminMqttPublishMax {
				break
			}
		}
		if got != adminMqttPublishMax {
			t.Fatalf("broker saw %d publishes, want %d", got, adminMqttPublishMax)
		}
	})

	t.Run("read-only session is its own action", func(t *testing.T) {
		since := maxID()
		c, _, err := dial(s.cfg.BaseURL)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		if err := c.WriteJSON(adminMqttInboundMsg{Type: "subscribe", Pattern: "thesada/#"}); err != nil {
			t.Fatal(err)
		}
		await(t, c, "info", "subscribed: thesada/#")
		_ = c.Close()
		d := auditAfter(t, "mqtt.shell_subscribe", since)
		if d["publishes"] != float64(0) {
			t.Fatalf("publishes = %v, want 0", d["publishes"])
		}
	})
}
