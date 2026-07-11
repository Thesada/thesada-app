// Package v1 serves the versioned JSON REST API at /api/v1/.
// All handlers are thin wrappers around pkg/service - no business logic here.
// Both the HTMX dashboard (via pkg/web) and the Flutter app consume this same
// API; pkg/web bypasses HTTP and calls services directly for performance, but
// the contracts must match.
package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/httpsec"
	"thesada.app/app/pkg/pki"
	"thesada.app/app/pkg/service"
)

// deviceCertValidity is the lifetime of a device client cert issued by the
// /pair endpoint. Matches pkg/web.deviceCertValidity - keep in sync.
const deviceCertValidity = 365 * 24 * time.Hour

// Server holds the JSON API handler tree.
type Server struct {
	cfg      *config.Config
	services *service.Services
	ca       *pki.CA
	mux      *http.ServeMux

	// Health probes, wired by SetHealthProbes. Closures so this package
	// stays free of db/mqtt imports.
	dbPing       func(context.Context) error
	brokerStatus func() string
}

// New constructs the API server with all routes wired up.
// in: cfg, services bundle, CA for pair endpoint. out: ready *Server.
func New(cfg *config.Config, services *service.Services, ca *pki.CA) *Server {
	s := &Server{cfg: cfg, services: services, ca: ca, mux: http.NewServeMux()}
	s.routes()
	return s
}

// ServeHTTP dispatches to the internal mux.
// Routes are registered relative; main.go mounts this under /api/v1/.
// in: writer, request. out: JSON response from matched handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// routes registers every JSON endpoint exposed by /api/v1/.
// in: receiver. out: none (mutates s.mux).
func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("GET /readyz", s.handleReady)
	s.mux.HandleFunc("POST /auth/login", s.handleAuthLogin)
	s.mux.HandleFunc("POST /auth/logout", s.handleAuthLogout)
	s.mux.HandleFunc("POST /auth/magic-link", s.handleAuthMagicLink)
	s.mux.HandleFunc("POST /auth/signup", s.handleAuthSignup)
	s.mux.HandleFunc("GET /devices", authmw.RequireAuthJSON(s.handleDeviceList))
	s.mux.HandleFunc("GET /devices/{id}", authmw.RequireAuthJSON(s.handleDeviceGet))
	s.mux.HandleFunc("POST /devices/{id}/pair", authmw.RequireSuperAdminJSON(s.handleDevicePair))
	s.mux.HandleFunc("GET /devices/{id}/telemetry", authmw.RequireAuthJSON(s.handleDeviceTelemetry))
	s.mux.HandleFunc("GET /devices/{id}/alerts", authmw.RequireAuthJSON(s.handleDeviceAlerts))
	s.mux.HandleFunc("GET /alerts", authmw.RequireAuthJSON(s.handleAlertList))
	s.mux.HandleFunc("GET /alert-subscriptions", authmw.RequireAuthJSON(s.handleSubsList))
	s.mux.HandleFunc("POST /alert-subscriptions", authmw.RequireAuthJSON(s.handleSubsCreate))
	s.mux.HandleFunc("DELETE /alert-subscriptions/{id}", authmw.RequireAuthJSON(s.handleSubsDelete))
}

// SetHealthProbes wires the dependency checks the health endpoints report.
// Both may be nil; the component then reports "unknown".
// in: dbPing (short-timeout DB reachability), brokerStatus ("disabled"/"up"/"down").
func (s *Server) SetHealthProbes(dbPing func(context.Context) error, brokerStatus func() string) {
	s.dbPing = dbPing
	s.brokerStatus = brokerStatus
}

// componentHealth runs the wired probes.
// out: db + mqtt component states, and readiness (db ok, broker up or
// deliberately disabled).
func (s *Server) componentHealth(ctx context.Context) (dbState, mqttState string, ready bool) {
	dbState, mqttState = "unknown", "unknown"
	if s.dbPing != nil {
		if err := s.dbPing(ctx); err != nil {
			dbState = "down"
		} else {
			dbState = "ok"
		}
	}
	if s.brokerStatus != nil {
		mqttState = s.brokerStatus()
	}
	ready = dbState != "down" && mqttState != "down"
	return dbState, mqttState, ready
}

// handleHealth is the API liveness probe: 200 as long as the process serves
// HTTP, with per-component detail. Never non-200 for a broker/DB outage -
// that would turn an infra blip into a container restart loop; /readyz
// carries the gating signal.
// in: writer, request. out: 200 with {"status","db","mqtt"}.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	dbState, mqttState, _ := s.componentHealth(r.Context())
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "ok", "db": dbState, "mqtt": mqttState,
	})
}

// handleReady is the readiness probe: 503 while the DB is unreachable or the
// broker connection is down. A disabled broker (no URL configured) does not
// fail readiness.
// in: writer, request. out: 200/503 with the same component JSON.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	dbState, mqttState, ready := s.componentHealth(r.Context())
	status, code := "ready", http.StatusOK
	if !ready {
		status, code = "degraded", http.StatusServiceUnavailable
	}
	writeJSON(w, code, map[string]string{
		"status": status, "db": dbState, "mqtt": mqttState,
	})
}

// pairResponse is the JSON body returned from POST /devices/{id}/pair.
// Private key is returned exactly once; it is not stored server-side.
type pairResponse struct {
	CN         string    `json:"cn"`
	SerialHex  string    `json:"serial_hex"`
	NotBefore  time.Time `json:"not_before"`
	NotAfter   time.Time `json:"not_after"`
	CertPEM    string    `json:"cert_pem"`
	PrivateKey string    `json:"private_key_pem"`
	CAPEM      string    `json:"ca_pem"`
}

// handleDevicePair signs a new device client certificate, persists it via
// CertificateService, and returns the PEM + private key to the caller.
// Does NOT push to the device - that happens either through the admin UI
// or through a separate caller-driven flow. Super-admin only.
// in: writer, POST /devices/{id}/pair. out: 200 JSON pairResponse, or error.
func (s *Server) handleDevicePair(w http.ResponseWriter, r *http.Request) {
	if s.ca == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "CA not initialized"})
		return
	}
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad device id"})
		return
	}
	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil {
		// A real backend error must return 500, not a 404 that hides the outage.
		slog.Error("api pair: device lookup failed", "device", id, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "device lookup failed"})
		return
	}
	if device == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return
	}

	cn := fmt.Sprintf("thesada-%s-%s", device.TenantID, device.DeviceID)
	certPEM, keyPEM, serialHex, err := s.ca.SignDeviceCert(cn, deviceCertValidity)
	if err != nil {
		slog.Error("api pair: sign failed", "device", device.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign failed"})
		return
	}
	now := time.Now()
	notAfter := now.Add(deviceCertValidity)
	if err := s.services.Certificates.Issue(r.Context(), device.TenantID, device.ID, serialHex, cn, now, notAfter, certPEM); err != nil {
		slog.Error("api pair: persist failed", "device", device.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "persist failed"})
		return
	}

	user := authmw.CurrentUser(r)
	slog.Info("api pair issued",
		"user", user.Email, "device", device.DeviceID, "tenant", device.TenantID,
		"cn", cn, "serial", serialHex)

	writeJSON(w, http.StatusOK, pairResponse{
		CN:         cn,
		SerialHex:  serialHex,
		NotBefore:  now,
		NotAfter:   notAfter,
		CertPEM:    certPEM,
		PrivateKey: keyPEM,
		CAPEM:      s.ca.CertPEMString(),
	})
}

// Auth handlers live in auth.go; device-read in devices.go; alert + alert-
// subscription handlers in alerts.go.
//
// magic-link is the one remaining stub (501): it needs the web layer's email
// templates + rate-limiters + mailer, deferred.

func (s *Server) handleAuthMagicLink(w http.ResponseWriter, r *http.Request) { stub(w) }

// writeJSON writes a JSON body with the given status code.
// in: writer, http status, payload to encode. out: none (best-effort write).
func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

// stub writes a 501 JSON error.
// in: writer. out: 501 with {"error":"not implemented"}.
func stub(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not implemented"})
}

// decodeJSON decodes the request body into dst, writing a 400 JSON error on
// malformed input. Shared by the handlers that take a JSON body.
// in: writer, request, destination pointer. out: true on success.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
		return false
	}
	return true
}

// clientIP resolves the request's client IP, honouring X-Forwarded-For from a
// configured trusted proxy.
// in: request. out: ip string or "".
func (s *Server) clientIP(r *http.Request) string {
	return httpsec.ClientIP(r, s.cfg.TrustedProxies)
}
