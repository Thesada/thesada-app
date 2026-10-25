// Super-admin MQTT shell. Subscribe pane taps the shared
// mqtt.Client's fanout registry; publish pane forwards to PublishRaw with
// a tenant-prefix guard so non-super-admin callers cannot blast other
// tenants' topic trees.
package web

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/authz"
	"thesada.app/app/pkg/httpsec"
	"thesada.app/app/pkg/ratelimit"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/ws"
)

// adminMqttMaxBuffer caps the per-socket outbound channel. When full, new
// messages are dropped and a `dropped` counter is surfaced so the browser
// knows it missed traffic.
const adminMqttMaxBuffer = 256

// adminMqttAuditCap bounds the topics and patterns one session's audit row
// lists; the publish count stays exact.
const adminMqttAuditCap = 50

// adminMqttPublishMax is the per-socket publish rate limit window + count.
const (
	adminMqttPublishWindow = 10 * time.Second
	adminMqttPublishMax    = 20
)

// adminMqttInboundMsg is the browser -> server message envelope. Type is
// either "subscribe" (pattern only) or "publish" (topic, payload, qos, retain).
type adminMqttInboundMsg struct {
	Type    string `json:"type"`
	Pattern string `json:"pattern"`
	Topic   string `json:"topic"`
	Payload string `json:"payload"`
	QoS     int    `json:"qos"`
	Retain  bool   `json:"retain"`
}

// adminMqttOutboundMsg is the server -> browser envelope.
type adminMqttOutboundMsg struct {
	Type      string `json:"type"`
	Topic     string `json:"topic,omitempty"`
	Payload   string `json:"payload,omitempty"`
	Retained  bool   `json:"retained,omitempty"`
	QoS       int    `json:"qos,omitempty"`
	Timestamp int64  `json:"ts,omitempty"`
	Error     string `json:"error,omitempty"`
	Info      string `json:"info,omitempty"`
	Dropped   int    `json:"dropped,omitempty"`
}

// handleAdminMqttShell renders the /admin/mqtt page (subscribe feed +
// publish form). The actual stream runs over the /admin/mqtt/ws websocket.
// in: writer, request. out: HTML page.
func (s *Server) handleAdminMqttShell(w http.ResponseWriter, r *http.Request) {
	root := s.cfg.MQTTTopicRoot
	s.render(w, r, "admin-mqtt.html", map[string]interface{}{
		"DefaultPattern": root + "/" + authmw.EffectiveTenantID(r) + "/#",
		"TopicRoot":      root,
	})
}

// handleAdminMqttWS upgrades to a WebSocket, registers a tap on the shared
// mqtt.Client on first subscribe message, and forwards matching traffic.
// Publish messages go through PublishRaw with a tenant prefix guard so a
// hostile browser can't cross-tenant publish.
// in: writer, request. out: websocket lifetime.
func (s *Server) handleAdminMqttWS(w http.ResponseWriter, r *http.Request) {
	if s.mqtt == nil {
		http.Error(w, "mqtt client not configured", http.StatusServiceUnavailable)
		return
	}
	upgrader := websocket.Upgrader{
		ReadBufferSize:  4096,
		WriteBufferSize: 4096,
		CheckOrigin: func(r *http.Request) bool {
			if httpsec.OriginAllowed(r, s.cfg.BaseURL) {
				return true
			}
			slog.Warn("ws.origin_rejected", "scope", "admin_mqtt", "origin", r.Header.Get("Origin"), "remote", r.RemoteAddr)
			return false
		},
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("admin mqtt ws upgrade failed", "err", err)
		return
	}
	user := authmw.CurrentUser(r)
	if user == nil {
		// RequireSuperAdmin makes this unreachable; if middleware regresses,
		// fail closed instead of granting the unrestricted root prefix.
		slog.Error("admin mqtt ws: no user in context, closing")
		_ = conn.Close()
		return
	}
	// The route is super-admin only (RequireSuperAdmin), so the whole tree
	// under the topic root is in scope; nothing outside it.
	root := s.cfg.MQTTTopicRoot
	allowedPrefix := root + "/"

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	// One admin_audit row per ws session, written on close - never per
	// message, or a busy shell would flood the table. It names the first
	// adminMqttAuditCap topics with payload sizes (never payloads: they can
	// carry secrets, and the table is append-only) and every pattern read.
	// Fresh context: the request/ws contexts are canceled by then.
	var (
		publishes  int
		published  []map[string]any
		subscribed []string
	)
	defer func() {
		if publishes == 0 && len(subscribed) == 0 {
			return
		}
		action := authz.MQTTShellPublish
		if publishes == 0 {
			action = authz.MQTTShellSubscribe
		}
		actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer acancel()
		s.audit(actx, user, action, service.AuditEntry{
			Detail: map[string]any{
				"publishes":  publishes,
				"published":  published,
				"truncated":  publishes > len(published),
				"subscribed": subscribed,
			},
		})
	}()

	// Outbound queue: the tap sink pushes here, the writer goroutine drains.
	out := make(chan adminMqttOutboundMsg, adminMqttMaxBuffer)
	var dropped int
	var dropMu sync.Mutex

	var (
		tapMu     sync.Mutex
		tapCancel func()
	)
	registerTap := func(pattern string) error {
		tapMu.Lock()
		defer tapMu.Unlock()
		if tapCancel != nil {
			tapCancel()
			tapCancel = nil
		}
		cancelFn, err := s.mqtt.RegisterTap(pattern, func(topic string, payload []byte, retained bool, qos byte) {
			msg := adminMqttOutboundMsg{
				Type:      "message",
				Topic:     topic,
				Payload:   string(payload),
				Retained:  retained,
				QoS:       int(qos),
				Timestamp: time.Now().UnixMilli(),
			}
			select {
			case out <- msg:
			default:
				dropMu.Lock()
				dropped++
				dropMu.Unlock()
			}
		})
		if err != nil {
			return err
		}
		tapCancel = cancelFn
		return nil
	}
	defer func() {
		tapMu.Lock()
		if tapCancel != nil {
			tapCancel()
			tapCancel = nil
		}
		tapMu.Unlock()
	}()

	// Writer goroutine: drains out channel onto the websocket. Closes when
	// ctx cancels or a write fails.
	go func() {
		defer func() { _ = conn.Close() }()
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		// Same cap as /ws: the shell reconnects and passes RequireSuperAdmin
		// again, so a demoted admin loses it within ws.MaxLifetime.
		lifetime := time.NewTimer(ws.MaxLifetime)
		defer lifetime.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case msg := <-out:
				// Surface drop count opportunistically so the browser sees
				// back-pressure events.
				dropMu.Lock()
				if dropped > 0 {
					msg.Dropped = dropped
					dropped = 0
				}
				dropMu.Unlock()
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := conn.WriteJSON(msg); err != nil {
					return
				}
			case <-ticker.C:
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				if err := conn.WriteMessage(websocket.PingMessage, nil); err != nil {
					return
				}
			case <-lifetime.C:
				_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
				_ = conn.WriteMessage(websocket.CloseMessage,
					websocket.FormatCloseMessage(ws.ReauthCloseCode, "reauthenticate"))
				return
			}
		}
	}()

	// Per-socket publish limiter: 20 publishes / 10s. Keyed by remote
	// addr so a browser that opens two tabs gets two independent buckets.
	pubLimiter := ratelimit.New(adminMqttPublishWindow, adminMqttPublishMax)
	pubKey := r.RemoteAddr

	// Reader loop: waits for subscribe / publish frames from the browser.
	for {
		var in adminMqttInboundMsg
		if err := conn.ReadJSON(&in); err != nil {
			cancel()
			return
		}
		switch in.Type {
		case "subscribe":
			pattern := strings.TrimSpace(in.Pattern)
			if pattern == "" {
				pattern = root + "/#"
			}
			if err := registerTap(pattern); err != nil {
				out <- adminMqttOutboundMsg{Type: "error", Error: "bad pattern: " + err.Error()}
				continue
			}
			if len(subscribed) < adminMqttAuditCap {
				subscribed = append(subscribed, pattern)
			}
			out <- adminMqttOutboundMsg{Type: "info", Info: "subscribed: " + pattern}
		case "publish":
			topic := strings.TrimSpace(in.Topic)
			if topic == "" || !strings.HasPrefix(topic, allowedPrefix) {
				out <- adminMqttOutboundMsg{Type: "error", Error: "topic must start with " + allowedPrefix}
				continue
			}
			if !pubLimiter.Allow(pubKey) {
				out <- adminMqttOutboundMsg{Type: "error", Error: "publish rate limit (20 / 10s) exceeded"}
				continue
			}
			qos := byte(0)
			if in.QoS >= 0 && in.QoS <= 2 {
				qos = byte(in.QoS)
			}
			if err := s.mqtt.PublishRaw(topic, []byte(in.Payload), qos, in.Retain); err != nil {
				out <- adminMqttOutboundMsg{Type: "error", Error: "publish failed: " + err.Error()}
				slog.Warn("admin mqtt publish failed", "topic", topic, "err", err)
				continue
			}
			publishes++
			if len(published) < adminMqttAuditCap {
				published = append(published, map[string]any{
					"topic": topic, "bytes": len(in.Payload), "retain": in.Retain,
				})
			}
			slog.Info("admin mqtt publish",
				"user", func() string {
					if user == nil {
						return ""
					}
					return user.Email
				}(),
				"topic", topic,
				"payload_len", len(in.Payload),
				"qos", qos,
				"retain", in.Retain)
			out <- adminMqttOutboundMsg{Type: "info", Info: "published " + topic}
		default:
			out <- adminMqttOutboundMsg{Type: "error", Error: "unknown type: " + in.Type}
		}
	}
}
