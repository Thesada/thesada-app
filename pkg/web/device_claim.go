package web

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

// Self-service device claiming.
//
// This is a claim-BY-TOKEN form, not a browsable list of unclaimed devices,
// and that is a security decision rather than a UI preference.
//
// Enrollments have no tenant until they are claimed, so any list of them is
// inherently cross-tenant. Showing one would let any authenticated user claim
// any device on the deployment the moment they know its id - and device ids
// are derived from sequentially-assigned factory MACs, so holding one unit
// tells you its neighbours' ids. The authz model cannot express the rule we
// actually want either: Can() is `superAdminActions[a] && u.IsSuperAdmin`, so
// a new action is either super-admin-only or open to everyone.
//
// Requiring the claim token from the device's own QR makes physical possession
// the authorisation, which is the property we want and the only one available.

// claimRateWindow is the rolling window the per-user claim cap is measured
// over. The cap itself is THESADA_DEVICE_CLAIM_MAX_PER_HOUR (default 5, the
// figure the spec names) so a fleet rollout can raise it without a rebuild.
const claimRateWindow = time.Hour

// claimRateFallback applies when the config carries no positive cap - a
// zero-valued Config in a test, not a deployment. Fail to the spec'd number
// rather than to "unlimited".
const claimRateFallback = 5

// handleDeviceClaimForm renders the claim form.
func (s *Server) handleDeviceClaimForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "device-claim.html", map[string]interface{}{
		"Title": "Claim a device",
	})
}

// handleDeviceClaimSubmit claims a verified enrollment into the current user's
// tenant, creates the devices row, and provisions the broker client.
//
// Order matters and is not arbitrary:
//  1. ClaimInto - one transaction, enrollment flip + devices row together.
//  2. dynsec - a network call, idempotent, retried independently.
//
// The certificate is NOT issued here. The device fetches it itself from the
// enrollment API once this marks the row claimed, which is what keeps the
// private key off this request path entirely.
func (s *Server) handleDeviceClaimSubmit(w http.ResponseWriter, r *http.Request) {
	user := authmw.CurrentUser(r)
	if user == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	tenantID := authmw.EffectiveTenantID(r)
	if tenantID == "" {
		s.claimError(w, r, "no tenant on this session")
		return
	}

	deviceID := strings.TrimSpace(r.FormValue("device_id"))
	claimToken := strings.TrimSpace(r.FormValue("claim_token"))
	if deviceID == "" || claimToken == "" {
		s.claimError(w, r, "device id and claim token are both required")
		return
	}
	if !s.claimLimits.Allow(user.ID.String()) {
		s.claimError(w, r, "too many claim attempts, try again later")
		return
	}

	// This form is the one place a claim token has to select a row on its own:
	// a human cannot supply the pubkey the device-facing endpoints key on. A
	// device_id can carry several enrollments - one per keypair that announced
	// under it, see migration 0028 - and the token is not unique across them,
	// so an ambiguous match is refused rather than resolved.
	e, err := s.services.Enrollments.FindForClaim(r.Context(), deviceID, claimToken)
	if err != nil {
		if errors.Is(err, service.ErrEnrollAmbiguous) {
			slog.Warn("device.enroll.claim_refused", "reason", "ambiguous_token",
				"user", user.ID, "device_id", deviceID)
			s.claimError(w, r,
				"more than one device is waiting with that id and code, so this claim was not made. Ask an operator to clear the duplicates")
			return
		}
		// Unknown device and wrong token give the same answer: this form must
		// not confirm whether a device id exists.
		slog.Info("device.enroll.claim_refused", "reason", "no_match",
			"user", user.ID, "device_id", deviceID, "err", err)
		s.claimError(w, r, "no device is waiting with that id and token")
		return
	}
	if e.VerifiedAt == nil {
		// The device has not proved it holds the key yet. Claiming now would
		// bind hardware that may not be the device on the label.
		s.claimError(w, r, "device has not finished announcing itself yet, try again shortly")
		return
	}

	topicPrefix := s.deviceClaimTopicPrefix(tenantID, deviceID)
	devicePk, err := s.services.Enrollments.ClaimInto(
		r.Context(), deviceID, e.PubkeyHex, tenantID, user.ID, topicPrefix)
	if err != nil {
		if errors.Is(err, service.ErrEnrollNotReady) {
			s.claimError(w, r, "that device has already been claimed")
			return
		}
		slog.Error("device.enroll.claim_failed", "user", user.ID, "device_id", deviceID, "err", err)
		s.claimError(w, r, "claim failed")
		return
	}

	// Broker provisioning. A failure here is a hard error surfaced to the user
	// rather than a warning: without the dynsec client the device's future
	// certificate is inert and it would silently never connect. Retrying the
	// claim is what fixes it, and the retry works: ClaimInto replays a row
	// already claimed by this tenant and owner instead of refusing it, and the
	// dynsec calls tolerate "already exists".
	cn := service.DeviceCertCN(tenantID, deviceID)
	dynsecCtx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if step, err := s.provisionDeviceDynsec(dynsecCtx, tenantID, deviceID, topicPrefix, cn); err != nil {
		slog.Error("device.enroll.dynsec_failed",
			"device_id", deviceID, "tenant", tenantID, "step", step, "err", err)
		s.claimError(w, r, "device claimed but broker provisioning failed, retry the claim")
		return
	}

	slog.Info("device.enroll.state_change",
		"from", "verified", "to", "claimed",
		"device_id", deviceID, "tenant", tenantID,
		"user", user.ID, "device_pk", devicePk, "reason", "user_claim")
	http.Redirect(w, r, "/devices?claimed="+deviceID, http.StatusFound)
}

// deviceClaimTopicPrefix delegates to the shared builder so the ACL written
// here and the prefix handed to the device are the same string by
// construction, not by two matching format strings.
func (s *Server) deviceClaimTopicPrefix(tenantID, deviceID string) string {
	root := ""
	if s.cfg != nil {
		root = s.cfg.MQTTTopicRoot
	}
	return service.DeviceTopicPrefix(root, tenantID, deviceID)
}

// claimError re-renders the form with a message. Deliberately vague about
// which half was wrong.
func (s *Server) claimError(w http.ResponseWriter, r *http.Request, msg string) {
	w.WriteHeader(http.StatusBadRequest)
	s.render(w, r, "device-claim.html", map[string]interface{}{
		"Title": "Claim a device",
		"Error": msg,
	})
}

// newClaimLimiter builds the per-user claim limiter. The caller starts its
// sweeper alongside the other limiters in New.
// in: cfg (may be nil in tests). out: limiter.
func newClaimLimiter(cfg *config.Config) *ratelimit.Limiter {
	max := claimRateFallback
	if cfg != nil && cfg.DeviceClaimMaxPerHour > 0 {
		max = cfg.DeviceClaimMaxPerHour
	}
	return ratelimit.New(claimRateWindow, max)
}
