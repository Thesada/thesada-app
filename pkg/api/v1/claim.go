package v1

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/ratelimit"
	"thesada.app/app/pkg/service"
)

// claimRateWindow matches the HTML form. The cap is the same config field.
const claimRateWindow = time.Hour

const claimRateFallback = 5

// newClaimLimiter uses the same cap as the form. A nil or zero config
// falls back to the spec figure rather than to unlimited.
func newClaimLimiter(cfg *config.Config) *ratelimit.Limiter {
	max := claimRateFallback
	if cfg != nil && cfg.DeviceClaimMaxPerHour > 0 {
		max = cfg.DeviceClaimMaxPerHour
	}
	return ratelimit.New(claimRateWindow, max)
}

type claimRequest struct {
	DeviceID   string `json:"device_id"`
	ClaimToken string `json:"claim_token"`
}

// handleDeviceClaim claims a verified enrollment for the session's tenant.
// in: JSON device_id and claim_token, authenticated user. out: JSON status.
func (s *Server) handleDeviceClaim(w http.ResponseWriter, r *http.Request) {
	user := authmw.CurrentUser(r)
	tenantID := authmw.EffectiveTenantID(r)
	if tenantID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no tenant on this session"})
		return
	}

	var req claimRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	deviceID := strings.TrimSpace(req.DeviceID)
	claimToken := strings.TrimSpace(req.ClaimToken)
	if deviceID == "" || claimToken == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "device id and claim token are both required",
		})
		return
	}
	if s.claimLimits == nil || !s.claimLimits.Allow(user.ID.String()) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{
			"error": "too many claim attempts, try again later",
		})
		return
	}
	if s.claimProvision == nil || s.services == nil || s.services.Enrollments == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "claim is not available"})
		return
	}

	e, err := s.services.Enrollments.FindForClaim(r.Context(), deviceID, claimToken)
	if err != nil {
		s.writeClaimFindError(w, user, deviceID, err)
		return
	}
	if e.VerifiedAt == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "device has not finished announcing itself yet, try again shortly",
		})
		return
	}

	root := ""
	if s.cfg != nil {
		root = s.cfg.MQTTTopicRoot
	}
	topicPrefix := service.DeviceTopicPrefix(root, tenantID, deviceID)
	devicePk, err := s.services.Enrollments.ClaimInto(
		r.Context(), deviceID, e.PubkeyHex, tenantID, user.ID, topicPrefix)
	if err != nil {
		code, msg := claimIntoHTTP(err)
		if code == http.StatusBadRequest && msg == "claim failed" {
			slog.Error("device.enroll.claim_failed", "user", user.ID, "device_id", deviceID, "err", err)
		}
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}

	cn := service.DeviceCertCN(tenantID, deviceID)
	dynsecCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if step, err := s.claimProvision(dynsecCtx, tenantID, deviceID, topicPrefix, cn); err != nil {
		slog.Error("device.enroll.dynsec_failed",
			"device_id", deviceID, "tenant", tenantID, "step", step, "err", err)
		code, msg := claimDynsecHTTP()
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}

	slog.Info("device.enroll.state_change",
		"from", "verified", "to", "claimed",
		"device_id", deviceID, "tenant", tenantID,
		"user", user.ID, "device_pk", devicePk, "reason", "user_claim")
	writeJSON(w, http.StatusOK, map[string]any{
		"device_id": deviceID,
		"id":        devicePk,
		"status":    "claimed",
	})
}

// claimIntoHTTP maps a failed ClaimInto. Cap and already-claimed are conflicts.
// in: ClaimInto error. out: status, message.
func claimIntoHTTP(err error) (int, string) {
	if errors.Is(err, service.ErrQuotaDevices) {
		return http.StatusConflict, "this tenant is at its device cap"
	}
	if errors.Is(err, service.ErrEnrollNotReady) {
		return http.StatusConflict, "that device has already been claimed"
	}
	return http.StatusBadRequest, "claim failed"
}

// claimDynsecHTTP is the retry answer when the row is claimed and the broker is not.
// in: none. out: status, message.
func claimDynsecHTTP() (int, string) {
	return http.StatusBadGateway, "device claimed but broker provisioning failed, retry the claim"
}

func (s *Server) writeClaimFindError(w http.ResponseWriter, user *service.User, deviceID string, err error) {
	switch {
	case errors.Is(err, service.ErrEnrollClaimLocked):
		slog.Warn("device.enroll.claim_refused", "reason", "locked",
			"user", user.ID, "device_id", deviceID)
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "too many wrong codes for that device. Restart the unit that finished announcing first, then retry",
		})
	case errors.Is(err, service.ErrEnrollAmbiguous):
		slog.Warn("device.enroll.claim_refused", "reason", "ambiguous_token",
			"user", user.ID, "device_id", deviceID)
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "more than one device is waiting with that id and code, so this claim was not made. Ask an operator to clear the duplicates",
		})
	default:
		slog.Info("device.enroll.claim_refused", "reason", "no_match",
			"user", user.ID, "device_id", deviceID, "err", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "no device is waiting with that id and token",
		})
	}
}
