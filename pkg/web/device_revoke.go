package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/authz"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/service"
)

// revokeVerdict is the outcome of the owner-revoke rule for one device.
type revokeVerdict int

const (
	revokeDenied  revokeVerdict = iota // not the caller's device: 404
	revokeNoOwner                      // admin-paired: admin revoke path only
	revokeNotHeld                      // claimed elsewhere since: that tenant's rows are not ours
	revokeAlready                      // unpaired and unclaimed: nothing left to revoke
	revokeAllowed
)

// revokeRefusal is the device-page message for each refusal that is not a 404.
var revokeRefusal = map[revokeVerdict]deviceFlashCode{
	revokeNoOwner: flashRevokeNoOwner,
	revokeNotHeld: flashRevokeNotHeld,
	revokeAlready: flashRevokeAlready,
}

// revokeGate: owner or super-admin, on a device that has an owner. Needs no
// enrollment read. in: caller, device. out: denied, no-owner, or allowed.
func revokeGate(me *service.User, d *service.Device) revokeVerdict {
	if me == nil || d == nil {
		return revokeDenied
	}
	isOwner := d.OwnerUserID != nil && *d.OwnerUserID == me.ID
	if !isOwner && !authz.Can(me, authz.CertRevoke) {
		return revokeDenied
	}
	if d.OwnerUserID == nil {
		return revokeNoOwner
	}
	return revokeAllowed
}

// decideRevoke: revokeGate, then the tenant must still hold the device id.
// in: caller, device, who holds the device id. out: verdict.
func decideRevoke(me *service.User, d *service.Device, hold service.DeviceHold) revokeVerdict {
	if v := revokeGate(me, d); v != revokeAllowed {
		return v
	}
	switch hold {
	case service.HoldElsewhere:
		return revokeNotHeld
	case service.HoldNone:
		return revokeAlready
	}
	return revokeAllowed
}

// revokeCheck runs decideRevoke, reading enrollment claims only past the gate.
// in: ctx, caller, device. out: verdict, error.
func (s *Server) revokeCheck(ctx context.Context, me *service.User, d *service.Device) (revokeVerdict, error) {
	if v := revokeGate(me, d); v != revokeAllowed {
		return v, nil
	}
	claimedBy, err := s.services.Enrollments.ClaimedTenants(ctx, d.DeviceID)
	if err != nil {
		return revokeDenied, err
	}
	return decideRevoke(me, d, service.DeviceHolder(d.TenantID, d.PairedAt != nil, claimedBy)), nil
}

// revokeConfirmed checks the typed confirmation against the device id.
// in: form value, device id. out: match.
func revokeConfirmed(typed, deviceID string) bool {
	return deviceID != "" && strings.TrimSpace(typed) == deviceID
}

// revokePath names who acted, for the audit row. in: caller, device. out: "owner" or "super_admin".
func revokePath(me *service.User, d *service.Device) string {
	if d.OwnerUserID != nil && *d.OwnerUserID == me.ID {
		return "owner"
	}
	return "super_admin"
}

// handleDeviceRevoke revokes a claimed device so it re-enrolls over HTTPS;
// order and refusals are in docs/invariants.md (owner revoke).
// in: writer, POST /devices/{id}/revoke with confirm_device_id. out: 302 to the device page.
func (s *Server) handleDeviceRevoke(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	me := authmw.CurrentUser(r)
	device, err := s.deviceInScope(r, id, authz.CertRevoke)
	if err != nil {
		slog.Error("device.revoke.lookup_failed", "id", id, "err", err)
		http.Error(w, "device get failed", http.StatusInternalServerError)
		return
	}
	verdict, err := s.revokeCheck(r.Context(), me, device)
	if err != nil {
		slog.Error("device.revoke.check_failed", "id", id, "err", err)
		http.Error(w, "revoke check failed", http.StatusInternalServerError)
		return
	}
	back := "/devices/" + id.String()
	if verdict == revokeDenied {
		http.NotFound(w, r)
		return
	}
	if refusal, refused := revokeRefusal[verdict]; refused {
		http.Redirect(w, r, refusal.on(back), http.StatusFound)
		return
	}
	if !revokeConfirmed(r.PostFormValue("confirm_device_id"), device.DeviceID) {
		http.Redirect(w, r, flashConfirmDeviceID.on(back), http.StatusFound)
		return
	}

	removed, err := s.services.Enrollments.ResetForTenant(r.Context(), device.DeviceID, device.TenantID)
	if errors.Is(err, service.ErrEnrollClaimedElsewhere) {
		http.Redirect(w, r, flashRevokeNotHeld.on(back), http.StatusFound)
		return
	}
	if err != nil {
		slog.Error("device.enroll.reset_failed", "op", "owner_revoke", "device_id", device.DeviceID, "err", err)
		http.Redirect(w, r, flashRevokeFailed.on(back), http.StatusFound)
		return
	}
	slog.Info("device.enroll.reset", "op", "owner_revoke", "device_id", device.DeviceID, "rows_deleted", removed)
	certErr := s.services.Certificates.Revoke(r.Context(), device.TenantID, device.ID)

	// The enrollment rows are gone either way, so the audit row is written
	// for both outcomes.
	ctx := context.WithoutCancel(r.Context())
	auditCtx, auditCancel := context.WithTimeout(ctx, auditTimeout)
	defer auditCancel()
	s.audit(auditCtx, me, authz.CertRevoke, service.AuditEntry{
		TargetType: "device", TargetID: device.ID.String(), TenantID: device.TenantID,
		Detail: map[string]any{
			"device_id": device.DeviceID, "path": revokePath(me, device),
			"enrollment_rows_deleted": removed, "cert_revoked": certErr == nil,
		},
	})
	if certErr != nil {
		slog.Error("device.revoke.cert_failed", "device", device.ID, "err", certErr)
		http.Redirect(w, r, flashRevokeCertFailed.on(back), http.StatusFound)
		return
	}
	if device.PairedAt != nil {
		logPairStateChange(device, "paired", "revoked", me.Email, "owner_revoke")
	}

	sent := ownerCertClear(s, device)
	s.teardownDeviceDynsec(ctx, device, "owner_revoke")

	if !sent {
		http.Redirect(w, r, flashRevokeUnsent.on(back), http.StatusFound)
		return
	}
	http.Redirect(w, r, flashRevoked.on(back), http.StatusFound)
}

// ownerCertClear publishes cert.clear alone: it drops the session, so nothing
// after it arrives. QoS 0, so true means sent, not received.
// in: server, device. out: published.
func ownerCertClear(s *Server, device *service.Device) bool {
	if device.MQTTTopicPrefix == nil || *device.MQTTTopicPrefix == "" {
		slog.Warn("device.revoke.cert_clear_skipped", "device", device.ID, "reason", "no_topic_prefix")
		return false
	}
	topic := mqtt.CLICommandTopic(*device.MQTTTopicPrefix, "cert.clear")
	if err := s.mqtt.PublishRaw(topic, []byte("{}"), 0, false); err != nil {
		slog.Warn("device.revoke.cert_clear_failed", "device", device.ID, "topic", topic, "err", err)
		return false
	}
	slog.Info("device.revoke.cert_clear_sent", "device", device.ID, "topic", topic)
	// The broker client must outlive the command's delivery.
	time.Sleep(800 * time.Millisecond)
	return true
}
