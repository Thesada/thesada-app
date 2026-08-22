package v1

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"time"

	"thesada.app/app/pkg/httpsec"
	"thesada.app/app/pkg/pki"
	"thesada.app/app/pkg/ratelimit"
	"thesada.app/app/pkg/service"
)

// Device self-enrollment.
//
// These four endpoints are the only unauthenticated device-facing surface in
// the app, and they are reachable from the public internet. Everything here is
// written on the assumption that the caller is hostile until it proves
// possession of the device key.
//
// The deliberate design constraint is that none of these endpoints may be used
// to learn anything. A caller who guesses a device_id must not be able to tell
// a real one from a fabricated one, so unknown device, wrong claim token,
// stale challenge and bad signature all produce the same response.

// Enrollment rate limits. Generous enough for a device retrying through a
// flaky first-boot WiFi connection, tight enough that the endpoint is not a
// free oracle to grind against.
const (
	enrollPerIPWindow   = time.Hour
	enrollPerIPMax      = 60
	enrollPerPairWindow = time.Hour
	enrollPerPairMax    = 30
	enrollPerIDWindow   = time.Hour
	enrollPerIDMax      = 30
)

// enrollLimiters bundles the three buckets this surface needs, each protecting
// a different thing: one host, one enrollment, one device_id's share of the
// table.
type enrollLimiters struct {
	byIP   *ratelimit.Limiter
	byPair *ratelimit.Limiter
	byID   *ratelimit.Limiter
}

// newEnrollLimiters builds the limiters and starts their sweepers
// (context.Background: process lifetime, same as the auth and magic-link
// limiters). The sweep is not housekeeping here - the keys come from body
// fields of an unauthenticated caller, so without it map growth is chosen by
// whoever is talking to the endpoint.
func newEnrollLimiters() *enrollLimiters {
	l := &enrollLimiters{
		byIP:   ratelimit.New(enrollPerIPWindow, enrollPerIPMax),
		byPair: ratelimit.New(enrollPerPairWindow, enrollPerPairMax),
		byID:   ratelimit.New(enrollPerIDWindow, enrollPerIDMax),
	}
	l.byIP.StartSweeper(context.Background())
	l.byPair.StartSweeper(context.Background())
	l.byID.StartSweeper(context.Background())
	return l
}

// enrollPairKey is the rate-limit key for one enrollment: the row's primary
// key. A device_id is a guessable MAC, the pubkey is not, so a caller who
// guessed an id cannot reach the budget of the device that owns it.
// in: device id, lowercase-hex pubkey. out: limiter key.
func enrollPairKey(deviceID, pubkeyHex string) string {
	return deviceID + "|" + pubkeyHex
}

// enrollClientIP extracts a rate-limit key: X-Forwarded-For via trusted
// proxies only (behind our proxy, RemoteAddr alone is one global bucket for
// the whole fleet), nil-cfg safe for tests, never empty.
// in: request. out: rate-limit key.
func (s *Server) enrollClientIP(r *http.Request) string {
	var trusted []*net.IPNet
	if s.cfg != nil {
		trusted = s.cfg.TrustedProxies
	}
	if ip := httpsec.ClientIP(r, trusted); ip != "" {
		return ip
	}
	return r.RemoteAddr
}

type enrollAnnounceReq struct {
	DeviceID   string `json:"device_id"`
	Pubkey     string `json:"pubkey"`
	ClaimToken string `json:"claim_token"`
}

// Every device-facing request names the row it means: (device_id, pubkey).
// The device always knows its own key, and nothing else on the wire identifies
// one row - claim tokens are not unique.
type enrollVerifyReq struct {
	DeviceID  string `json:"device_id"`
	Pubkey    string `json:"pubkey"`
	Signature string `json:"signature"`
}

type enrollCertReq struct {
	DeviceID   string `json:"device_id"`
	Pubkey     string `json:"pubkey"`
	ClaimToken string `json:"claim_token"`
}

// enrollReject is the single failure response for every "no" on this surface.
// One shape, one status, no detail: the caller learns that it failed and
// nothing about why. Splitting this into precise errors would turn the
// endpoint into a device enumeration oracle.
func enrollReject(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "enrollment refused"})
}

// enrollGate applies the per-IP and per-enrollment limits. Order is
// load-bearing: the IP budget is spent before body fields are validated or
// used as map keys, and every refusal is the same 403 (docs/invariants.md).
// in: writer, request, device id, lowercase-hex pubkey. out: true to proceed,
// false when the caller has already been answered.
func (s *Server) enrollGate(w http.ResponseWriter, r *http.Request, deviceID, pubkeyHex string) bool {
	if !s.enroll.byIP.Allow(s.enrollClientIP(r)) {
		slog.Info("device.enroll.rate_limited", "scope", "ip", "ip", s.enrollClientIP(r))
		enrollReject(w)
		return false
	}
	if !pki.ValidDeviceID(deviceID) {
		enrollReject(w)
		return false
	}
	if _, err := pki.ParseDevicePublicKey(pubkeyHex); err != nil {
		enrollReject(w)
		return false
	}
	if !s.enroll.byPair.Allow(enrollPairKey(deviceID, pubkeyHex)) {
		slog.Info("device.enroll.rate_limited", "scope", "enrollment", "device_id", deviceID)
		enrollReject(w)
		return false
	}
	return true
}

// enrollAnnounceGate is enrollGate plus the per-device_id cap, which announce
// alone spends because announce alone creates rows. It bounds how much of the
// table one guessable id can occupy without gating the endpoints an already
// announced device depends on.
// in: writer, request, device id, lowercase-hex pubkey. out: true to proceed.
func (s *Server) enrollAnnounceGate(w http.ResponseWriter, r *http.Request, deviceID, pubkeyHex string) bool {
	if !s.enrollGate(w, r, deviceID, pubkeyHex) {
		return false
	}
	if !s.enroll.byID.Allow(deviceID) {
		slog.Info("device.enroll.rate_limited", "scope", "device", "device_id", deviceID)
		enrollReject(w)
		return false
	}
	return true
}

// handleEnrollAnnounce records a device announcement and returns a challenge
// for it to sign. POST /devices/enroll, unauthenticated.
//
// Any well-formed device_id and pubkey get 200 and a challenge, always,
// whatever state the enrollment is in. Refusing a sealed or already-verified
// id would answer the one question this surface must never answer: which ids
// are real. Sealed, frozen and already-claimed surface at /enroll/verify
// instead, to a caller that has proved it holds the private key.
func (s *Server) handleEnrollAnnounce(w http.ResponseWriter, r *http.Request) {
	var req enrollAnnounceReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		enrollReject(w)
		return
	}
	if !s.enrollAnnounceGate(w, r, req.DeviceID, req.Pubkey) {
		return
	}
	challenge, err := s.services.Enrollments.Announce(r.Context(), req.DeviceID, req.Pubkey, req.ClaimToken)
	if err != nil {
		// Only a malformed pubkey or a database failure reaches here; state is
		// never a reason to refuse. Logged server-side either way.
		slog.Info("device.enroll.announce_refused", "device_id", req.DeviceID, "err", err)
		enrollReject(w)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"challenge":  challenge,
		"expires_in": int(service.ChallengeTTL.Seconds()),
	})
}

// handleEnrollVerify consumes the challenge and records proof of possession.
// POST /devices/enroll/verify, unauthenticated.
//
// This is where a sealed or frozen enrollment is refused, rather than at
// announce - but the refusal is still the uniform body. The state stays inside
// the process; a device that keeps being refused backs off, it does not need
// to be told which of the reasons applied.
func (s *Server) handleEnrollVerify(w http.ResponseWriter, r *http.Request) {
	var req enrollVerifyReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		enrollReject(w)
		return
	}
	if !s.enrollGate(w, r, req.DeviceID, req.Pubkey) {
		return
	}
	sig, err := hex.DecodeString(req.Signature)
	if err != nil {
		enrollReject(w)
		return
	}
	if err := s.services.Enrollments.Verify(r.Context(), req.DeviceID, req.Pubkey, sig); err != nil {
		slog.Info("device.enroll.verify_refused", "device_id", req.DeviceID, "err", err)
		enrollReject(w)
		return
	}
	slog.Info("device.enroll.state_change",
		"from", "announced", "to", "verified",
		"device_id", req.DeviceID, "reason", "device_proof")
	writeJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

// handleEnrollCert hands over the certificate once a human has claimed the
// device. POST /devices/enroll/cert, unauthenticated.
//
// 204 means "not yet claimed, keep polling" and is the normal case for most of
// this endpoint's life. It is deliberately indistinguishable from the response
// a verified-but-unclaimed device gets, so polling reveals nothing beyond what
// the caller already proved it knows.
func (s *Server) handleEnrollCert(w http.ResponseWriter, r *http.Request) {
	var req enrollCertReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		enrollReject(w)
		return
	}
	if !s.enrollGate(w, r, req.DeviceID, req.Pubkey) {
		return
	}
	// After the gate, and answered like every other refusal. A 503 here used
	// to be the one response an unauthenticated caller could get without
	// spending a rate-limit token, and it is a different shape from the rest.
	// The operator signal is the slog line, which is louder than a status code
	// nobody is watching.
	if s.ca == nil {
		slog.Error("device.enroll.ca_missing", "device_id", req.DeviceID)
		enrollReject(w)
		return
	}

	e, err := s.services.Enrollments.FindByDeviceKey(r.Context(), req.DeviceID, req.Pubkey, req.ClaimToken)
	if err != nil {
		// Unknown pair, wrong token and malformed id are one answer.
		slog.Info("device.enroll.cert_refused", "device_id", req.DeviceID, "err", err)
		enrollReject(w)
		return
	}
	if e.VerifiedAt == nil {
		enrollReject(w)
		return
	}
	if e.ClaimedAt == nil || e.ClaimedByTenant == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if e.CertDeliveredAt != nil {
		// Already redeemed. Recovering needs an explicit re-pair.
		enrollReject(w)
		return
	}

	tenant := *e.ClaimedByTenant
	device, err := s.services.Devices.GetByDeviceID(tenant, req.DeviceID)
	if err != nil || device == nil {
		// The claim step is responsible for creating this row. Its absence is
		// a server-side inconsistency, logged loudly - but the answer is the
		// uniform refusal, because whether a claimed devices row exists for an
		// id is exactly what the caller must not learn.
		slog.Error("device.enroll.device_row_missing",
			"device_id", req.DeviceID, "tenant", tenant, "err", err)
		enrollReject(w)
		return
	}

	// The two failures below stay 500. Neither depends on which device_id was
	// asked for, so neither distinguishes a real id from a fabricated one, and
	// a signing CA that cannot sign should look broken rather than picky.
	cn := service.DeviceCertCN(tenant, device.DeviceID)
	certPEM, keyPEM, serialHex, err := s.ca.SignDeviceCert(cn, deviceCertValidity)
	if err != nil {
		slog.Error("device.enroll.cert_sign_failed", "device_id", req.DeviceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "sign failed"})
		return
	}
	now := time.Now()
	if err := s.services.Certificates.Issue(r.Context(), tenant, device.ID,
		serialHex, cn, now, now.Add(deviceCertValidity), certPEM); err != nil {
		slog.Error("device.enroll.cert_persist_failed", "device_id", req.DeviceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "persist failed"})
		return
	}

	// NOT sealed here. The device acknowledges via /devices/enroll/ack once the
	// pair is stored and validated on its side; only that seals the row. See
	// EnrollmentService.MarkDelivered for why sealing at hand-over bricks a
	// device on any mid-flight failure.
	//
	// ca_pem is deliberately absent. It would be the private device CA, which
	// the broker uses to verify CLIENT certs; the device verifies the BROKER
	// against public roots it already carries. Returning it invites the
	// firmware to overwrite its own trust anchor and lose MQTT and OTA.
	// A cert with no broker to present it to is a device that fails silently at
	// its next connect, with nothing on the server side to see. Refuse loudly
	// instead - same posture as a signing CA that cannot sign.
	brokerHost, mtlsPort := s.enrollBrokerEndpoint()
	if brokerHost == "" {
		slog.Error("device.enroll.broker_host_missing", "device_id", req.DeviceID, "tenant", tenant)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "broker unconfigured"})
		return
	}

	slog.Info("device.enroll.cert_issued", "device_id", req.DeviceID, "tenant", tenant, "cn", cn)
	writeJSON(w, http.StatusOK, map[string]any{
		"cert_pem": certPEM,
		"key_pem":  keyPEM,
		// Without these the device holds a valid certificate it cannot use: the
		// CN, the broker ACL and the app's ingest are all keyed on the tenant,
		// and the firmware default topic prefix belongs to a different device.
		"tenant":       tenant,
		"device_id":    device.DeviceID,
		"topic_prefix": s.enrollTopicPrefix(tenant, device.DeviceID),
		"mqtt_host":    brokerHost,
		"mqtt_port":    mtlsPort,
	})
}

// enrollBrokerEndpoint is the broker host + mTLS port handed to the device.
// Nil-guarded like enrollTopicPrefix below: a Server built without cfg must
// refuse, not panic.
// in: receiver. out: hostname ("" when unconfigured), mTLS port.
func (s *Server) enrollBrokerEndpoint() (string, int) {
	if s.cfg == nil {
		return "", 0
	}
	return s.cfg.BrokerHost(), s.cfg.MQTTDeviceMTLSPort
}

// enrollTopicPrefix delegates to the shared builder the claim path also uses.
// The device is told this value rather than deriving it, because the firmware
// default prefix belongs to no tenant.
func (s *Server) enrollTopicPrefix(tenant, deviceID string) string {
	root := ""
	if s.cfg != nil {
		root = s.cfg.MQTTTopicRoot
	}
	return service.DeviceTopicPrefix(root, tenant, deviceID)
}

// handleEnrollAck seals the enrollment once the device confirms it stored and
// validated the certificate. POST /devices/enroll/ack, unauthenticated.
//
// This is what makes delivery safe to retry: until it lands, the cert endpoint
// re-issues, and each issue revokes the last.
func (s *Server) handleEnrollAck(w http.ResponseWriter, r *http.Request) {
	var req enrollCertReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&req); err != nil {
		enrollReject(w)
		return
	}
	if !s.enrollGate(w, r, req.DeviceID, req.Pubkey) {
		return
	}
	tenant, err := s.services.Enrollments.MarkDelivered(r.Context(),
		req.DeviceID, req.Pubkey, req.ClaimToken)
	if err != nil {
		if errors.Is(err, service.ErrEnrollNotFound) {
			// Unknown pair or a token that does not belong to it. Sealing is
			// terminal, so this one is refused rather than reported sealed.
			enrollReject(w)
			return
		}
		if errors.Is(err, service.ErrEnrollNotReady) {
			// Already sealed, or never deliverable. Idempotent either way.
			writeJSON(w, http.StatusOK, map[string]string{"status": "sealed"})
			return
		}
		slog.Error("device.enroll.seal_failed", "device_id", req.DeviceID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "seal failed"})
		return
	}
	slog.Info("device.enroll.state_change",
		"from", "claimed", "to", "delivered",
		"device_id", req.DeviceID, "tenant", tenant, "reason", "device_ack")
	writeJSON(w, http.StatusOK, map[string]string{"status": "sealed"})
}
