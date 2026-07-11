// Package ws is the WebSocket hub. MQTT messages flow in via Publish, then
// fan out as JSON frames to every connected browser for the same tenant.
// Auth is enforced by the caller: main.go wraps /ws in authmw.RequireAuth.
package ws

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/httpsec"
)

// writeTimeout is the deadline for a single frame write.
const writeTimeout = 10 * time.Second

// pingPeriod is how often the server pings the client to keep the connection alive.
const pingPeriod = 30 * time.Second

// pongWait is how long the server waits for a pong before dropping the client.
const pongWait = 60 * time.Second

// sendBuffer is the per-connection outbound queue depth before we drop frames.
const sendBuffer = 32

// Hub tracks active WebSocket connections and fans events out by tenant.
// Safe for concurrent use; one Hub per process.
type Hub struct {
	cfg      *config.Config
	upgrader websocket.Upgrader
	mu       sync.RWMutex
	conns    map[*conn]struct{}
}

// conn is one live browser WebSocket. send is drained by writePump; a full
// buffer means the consumer is slow and frames are dropped, never blocking Publish.
type conn struct {
	ws     *websocket.Conn
	send   chan []byte
	tenant string
}

// New constructs an empty Hub. The upgrader rejects cross-origin upgrades by
// validating the Origin header against cfg.BaseURL, so a hostile page cannot
// ride the browser's session cookie to open a socket (CSWSH). A missing Origin
// (non-browser client) is allowed; broaden BaseURL handling if a native client
// connects directly with its own Origin.
// in: cfg. out: ready *Hub.
func New(cfg *config.Config) *Hub {
	return &Hub{
		cfg:   cfg,
		conns: make(map[*conn]struct{}),
		upgrader: websocket.Upgrader{
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
			CheckOrigin: func(r *http.Request) bool {
				if httpsec.OriginAllowed(r, cfg.BaseURL) {
					return true
				}
				slog.Warn("ws.origin_rejected", "origin", r.Header.Get("Origin"), "remote", r.RemoteAddr)
				return false
			},
		},
	}
}

// ServeHTTP upgrades an authenticated HTTP request to a WebSocket connection
// and starts the read/write pumps. The handler expects authmw.RequireAuth to
// already have attached the current user to the request context.
// in: writer, request. out: hijacked socket or 401/500.
func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	if u == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	socket, err := h.upgrader.Upgrade(w, r, nil)
	if err != nil {
		slog.Error("ws upgrade failed", "err", err)
		return
	}
	// EffectiveTenantID, not u.TenantID: an impersonating super-admin must see
	// the impersonated tenant's events, not their home tenant's.
	cn := &conn{ws: socket, send: make(chan []byte, sendBuffer), tenant: authmw.EffectiveTenantID(r)}
	h.register(cn)
	slog.Info("ws client connected", "tenant", cn.tenant, "user", u.Email)
	go h.writePump(cn)
	go h.readPump(cn)
}

// Publish marshals event to JSON and queues it on every connection that
// belongs to the given tenant. Non-blocking: if a client buffer is full the
// frame is dropped for that client alone.
// in: tenant id, device id (unused today, included for future per-device filtering), event payload.
// out: none.
func (h *Hub) Publish(tenant, device string, event any) {
	_ = device
	payload, err := json.Marshal(event)
	if err != nil {
		slog.Error("ws marshal failed", "err", err)
		return
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for cn := range h.conns {
		if cn.tenant != tenant {
			continue
		}
		select {
		case cn.send <- payload:
		default:
			slog.Warn("ws client buffer full, dropping frame", "tenant", cn.tenant)
		}
	}
}

// register adds a new conn to the hub under the write lock.
// in: *conn. out: none.
func (h *Hub) register(cn *conn) {
	h.mu.Lock()
	h.conns[cn] = struct{}{}
	h.mu.Unlock()
}

// unregister removes a conn, closes its send channel, and shuts the socket.
// Safe to call more than once only if writePump/readPump coordinate, which they
// do by having exactly one of them invoke this.
// in: *conn. out: none.
func (h *Hub) unregister(cn *conn) {
	h.mu.Lock()
	if _, ok := h.conns[cn]; !ok {
		h.mu.Unlock()
		return
	}
	delete(h.conns, cn)
	h.mu.Unlock()
	close(cn.send)
	_ = cn.ws.Close()
}

// writePump drains cn.send onto the socket and keeps the connection warm with
// periodic pings. Exits on any write error or when the send channel closes.
// in: *conn. out: none.
func (h *Hub) writePump(cn *conn) {
	ticker := time.NewTicker(pingPeriod)
	defer func() {
		ticker.Stop()
		h.unregister(cn)
	}()
	for {
		select {
		case msg, ok := <-cn.send:
			_ = cn.ws.SetWriteDeadline(time.Now().Add(writeTimeout))
			if !ok {
				_ = cn.ws.WriteMessage(websocket.CloseMessage, nil)
				return
			}
			if err := cn.ws.WriteMessage(websocket.TextMessage, msg); err != nil {
				return
			}
		case <-ticker.C:
			_ = cn.ws.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err := cn.ws.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

// readPump discards inbound frames (browser never sends us data today) and
// exists to detect connection close so writePump can tear down cleanly.
// in: *conn. out: none.
func (h *Hub) readPump(cn *conn) {
	defer h.unregister(cn)
	cn.ws.SetReadLimit(512)
	_ = cn.ws.SetReadDeadline(time.Now().Add(pongWait))
	cn.ws.SetPongHandler(func(string) error {
		return cn.ws.SetReadDeadline(time.Now().Add(pongWait))
	})
	for {
		if _, _, err := cn.ws.ReadMessage(); err != nil {
			return
		}
	}
}
