// Bulk admin actions on /admin/devices. Covers bulk OTA, bulk tenant
// reassign, and bulk delete with a cross-tenant gate. Delete loops the
// single-device pipeline (cert revoke + dynsec teardown + DB cascade)
// per checked device.
// Cross-tenant submissions are rejected unless `confirm_cross_tenant=true`
// is set, to reduce blast radius of a misclick.
package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/authz"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/service"
)

// handleAdminDevicesBulk dispatches POST /admin/devices/bulk to the
// matching action. Form must contain `action` and zero-or-more
// repeated `device_ids` form values. Unknown actions redirect with an
// error query param so the user sees the failure inline.
// in: writer, POST form (action, device_ids[]). out: 302 to /admin/devices.
func (s *Server) handleAdminDevicesBulk(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	switch r.PostFormValue("action") {
	case "ota":
		s.bulkOTACheck(w, r)
	case "reassign":
		s.bulkReassign(w, r)
	case "delete":
		s.bulkDeleteDevices(w, r)
	default:
		http.Redirect(w, r, "/admin/devices?error=unknown+bulk+action", http.StatusFound)
	}
}

// bulkReassign moves every checked device into the target tenant via the
// existing single-device DeviceService.Reassign path. Per-device errors
// are counted and surfaced via the redirect query string; a unique-device
// collision in the target tenant fails just that one device, not the rest
// (matches slice 1 fire-and-forget semantics on purpose - operator can see
// the failed count and reconcile manually).
//
// Note: like the single-device reassign handler, this only updates the
// app-side row. The on-device mqtt.topic_prefix must be updated out of
// band so the device starts publishing on the new tenant's prefix.
// in: writer, request (device_ids[] + target_tenant in form). out: 302 to /admin/devices.
func (s *Server) bulkReassign(w http.ResponseWriter, r *http.Request) {
	ids := r.PostForm["device_ids"]
	if len(ids) == 0 {
		http.Redirect(w, r, "/admin/devices?error=no+devices+selected", http.StatusFound)
		return
	}
	target := r.PostFormValue("target_tenant")
	if target == "" || !s.services.Tenants.ExistsBySlug(target) {
		http.Redirect(w, r, "/admin/devices?error=unknown+tenant", http.StatusFound)
		return
	}
	user := authmw.CurrentUser(r)

	var ok, failed int
	for _, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil {
			failed++
			continue
		}
		if err := s.services.Devices.Reassign(r.Context(), id, target); err != nil {
			slog.Warn("bulk reassign: failed", "id", id, "target", target, "err", err)
			failed++
			continue
		}
		s.audit(r.Context(), user, authz.DeviceReassign, service.AuditEntry{
			TargetType: "device", TargetID: id.String(), TenantID: target,
			Detail: map[string]any{"target_tenant": target, "bulk": true},
		})
		ok++
	}
	slog.Info("admin bulk reassign dispatched",
		"user", user.Email, "target", target, "ok", ok, "failed", failed, "total", len(ids))

	http.Redirect(w, r,
		"/admin/devices?ok=reassigned+"+strconv.Itoa(ok)+
			"&failed="+strconv.Itoa(failed),
		http.StatusFound)
}

// bulkOTACheck publishes `cli/ota.check` with `--force` payload to every
// device whose primary key was checked in the form. Fire-and-forget; we
// do not wait for the device's CLI response because a fleet-wide bulk
// would otherwise block the request indefinitely on offline devices.
// Successes + failures are counted and surfaced via the redirect query
// string.
// in: writer, request (device_ids[] in form). out: 302 to /admin/devices.
func (s *Server) bulkOTACheck(w http.ResponseWriter, r *http.Request) {
	ids := r.PostForm["device_ids"]
	if len(ids) == 0 {
		http.Redirect(w, r, "/admin/devices?error=no+devices+selected", http.StatusFound)
		return
	}
	user := authmw.CurrentUser(r)

	var ok, failed int
	var okIDs, failedIDs []string
	for _, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil {
			failed++
			failedIDs = append(failedIDs, raw)
			continue
		}
		device, err := s.services.Devices.GetByIDAny(r.Context(), id)
		if err != nil {
			slog.Warn("bulk ota: device lookup failed", "id", id, "err", err)
			failed++
			failedIDs = append(failedIDs, raw)
			continue
		}
		topicPrefix := s.deviceTopicPrefix(device)
		cmdTopic := mqtt.CLICommandTopic(topicPrefix, "ota.check")
		if err := s.mqtt.PublishRaw(cmdTopic, []byte("--force"), 0, false); err != nil {
			slog.Warn("bulk ota: publish failed", "device", device.DeviceID, "topic", cmdTopic, "err", err)
			failed++
			failedIDs = append(failedIDs, device.DeviceID)
			continue
		}
		ok++
		okIDs = append(okIDs, device.DeviceID)
	}
	slog.Info("admin bulk ota dispatched",
		"user", user.Email, "ok", ok, "failed", failed, "total", len(ids))
	// One row for the whole dispatch, carrying WHICH devices got the command
	// (form selection, so bounded by the device list UI). Fire-and-forget:
	// there is no per-device outcome beyond publish success to record.
	s.audit(r.Context(), user, authz.OTADispatch, service.AuditEntry{
		TargetType: "devices",
		Detail: map[string]any{"ok": ok, "failed": failed, "total": len(ids),
			"ok_ids": okIDs, "failed_ids": failedIDs},
	})

	http.Redirect(w, r,
		"/admin/devices?ok=ota+dispatched+"+strconv.Itoa(ok)+
			"&failed="+strconv.Itoa(failed),
		http.StatusFound)
}

// bulkDeleteDevices loops the single-device delete pipeline (cert revoke
// + dynsec teardown + DB CASCADE) over every checked device. Cross-tenant
// gate: if the selection spans more than one tenant, rejects unless the
// form explicitly carries `confirm_cross_tenant=true`. Reduces blast
// radius of a misclick where the operator selects-all across tenants
// without realizing the breadth.
//
// Per-device errors are counted and surfaced via the redirect query
// string (matches the slice 1 / slice 2 fire-and-forget shape). One
// failed device does NOT abort the rest - the operator can re-submit
// the failed subset after diagnosing.
//
// in: writer, request (device_ids[] + optional confirm_cross_tenant in
// form). out: 302 to /admin/devices.
func (s *Server) bulkDeleteDevices(w http.ResponseWriter, r *http.Request) {
	ids := r.PostForm["device_ids"]
	if len(ids) == 0 {
		http.Redirect(w, r, "/admin/devices?error=no+devices+selected", http.StatusFound)
		return
	}
	confirmCrossTenant := r.PostFormValue("confirm_cross_tenant") == "true"
	user := authmw.CurrentUser(r)

	// First pass: resolve devices, detect cross-tenant span.
	type pending struct {
		id     uuid.UUID
		device *service.Device
	}
	resolved := make([]pending, 0, len(ids))
	tenants := make(map[string]struct{})
	var lookupFailed int
	for _, raw := range ids {
		id, err := uuid.Parse(raw)
		if err != nil {
			lookupFailed++
			continue
		}
		device, err := s.services.Devices.GetByIDAny(r.Context(), id)
		if err != nil {
			// Log a real backend error so a DB outage isn't silently counted as
			// "not found" (matches the bulk-ota loop; the counter still advances).
			slog.Warn("bulk resolve: device lookup failed", "id", id, "err", err)
			lookupFailed++
			continue
		}
		if device == nil {
			lookupFailed++
			continue
		}
		resolved = append(resolved, pending{id: id, device: device})
		tenants[device.TenantID] = struct{}{}
	}
	if len(resolved) == 0 {
		http.Redirect(w, r,
			"/admin/devices?error=no+resolvable+devices&failed="+strconv.Itoa(lookupFailed),
			http.StatusFound)
		return
	}
	if len(tenants) > 1 && !confirmCrossTenant {
		http.Redirect(w, r,
			"/admin/devices?error=cross+tenant+selection+blocked+(set+confirm_cross_tenant)",
			http.StatusFound)
		return
	}

	// Second pass: cascade per device. Each step bounded so a single
	// broker hiccup or DB hang doesn't pin the whole batch. One recovery
	// probe covers the batch; the gate is per device. Audit rows are written
	// on a context that outlives the request: the revoke they record is
	// already committed.
	v := s.recoveryPath(r.Context())
	override := acceptSerialRecovery(r)
	auditCtx := context.WithoutCancel(r.Context())
	var ok, failed, refused, sealed int
	failed = lookupFailed
	for _, p := range resolved {
		verdict := s.cascadeDeleteOne(r.Context(), user.Email, p.device, v, override)
		switch verdict {
		case cascadeRefused:
			refused++
			continue
		case cascadeFailed:
			failed++
			continue
		case cascadeOKSealed:
			sealed++
		}
		rowCtx, rowCancel := context.WithTimeout(auditCtx, auditTimeout)
		s.audit(rowCtx, user, authz.DeviceDelete, service.AuditEntry{
			TargetType: "device", TargetID: p.device.ID.String(), TenantID: p.device.TenantID,
			Detail: auditDetail(map[string]any{"device_id": p.device.DeviceID, "bulk": true},
				serialRecoveryAccepted(p.device.PairedAt != nil, v, override)),
		})
		rowCancel()
		ok++
	}
	slog.Info("admin bulk delete dispatched",
		"user", user.Email,
		"tenants", len(tenants),
		"cross_tenant", len(tenants) > 1,
		"ok", ok, "failed", failed, "refused", refused, "sealed", sealed, "total", len(ids))

	target := "/admin/devices?ok=deleted+" + strconv.Itoa(ok) + "&failed=" + strconv.Itoa(failed)
	var problems []string
	if refused > 0 {
		problems = append(problems, strconv.Itoa(refused)+" paired device(s) refused: "+v.reason+
			". Tick accept serial recovery to delete anyway")
	}
	if sealed > 0 {
		problems = append(problems, strconv.Itoa(sealed)+" deleted but enrollment reset failed, re-enrollment stays blocked")
	}
	if len(problems) > 0 {
		target += "&error=" + url.QueryEscape(strings.Join(problems, "; "))
	}
	http.Redirect(w, r, target, http.StatusFound)
}

// recoveryVerdict is one probe of the shared fallback credential.
type recoveryVerdict struct {
	usable bool
	reason string // operator-facing, set when not usable
}

// recoveryPath probes whether a device walked off mTLS could get back onto
// the broker on the shared fallback credential. One probe per request.
// in: ctx. out: verdict.
func (s *Server) recoveryPath(ctx context.Context) recoveryVerdict {
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	enabled, err := s.mqtt.DynsecClientEnabled(probeCtx, s.cfg.MQTTDeviceFallbackUser)
	if mqtt.RecoveryPathUsable(enabled, err) {
		return recoveryVerdict{usable: true}
	}
	if err != nil {
		return recoveryVerdict{reason: "fallback credential " + s.cfg.MQTTDeviceFallbackUser + " unreachable: " + err.Error()}
	}
	return recoveryVerdict{reason: "fallback credential " + s.cfg.MQTTDeviceFallbackUser + " is disabled at the broker"}
}

// destructiveAllowed refuses exactly one shape: a paired device, no usable
// path back onto the broker, no operator override.
// in: device is paired, recovery path usable, operator override. out: proceed.
func destructiveAllowed(paired, usable, override bool) bool {
	return !paired || usable || override
}

// acceptSerialRecovery reads the operator override from the form.
// in: request. out: override set.
func acceptSerialRecovery(r *http.Request) bool {
	return r.PostFormValue("accept_serial_recovery") == "true"
}

// serialRecoveryAccepted is true only when the override did the work: a
// paired device, no usable path, and the operator ticked the box. An unpaired
// device passes the gate without any acceptance, so nothing is recorded.
// in: device is paired, verdict, override. out: accepted.
func serialRecoveryAccepted(paired bool, v recoveryVerdict, override bool) bool {
	return paired && !v.usable && override
}

// recoveryGate runs the probe and the gate for one device on a single-device
// handler, writes the refusal redirect itself, and logs an accepted override.
// in: writer, request, device, op ("delete"|"revoke"), redirect base on
// refusal. out: verdict, override accepted, proceed.
func (s *Server) recoveryGate(w http.ResponseWriter, r *http.Request, device *service.Device, op, dest string) (recoveryVerdict, bool, bool) {
	v := s.recoveryPath(r.Context())
	override := acceptSerialRecovery(r)
	user := authmw.CurrentUser(r)
	paired := device.PairedAt != nil
	if !destructiveAllowed(paired, v.usable, override) {
		slog.Warn("device."+op+".refused", "reason", "recovery_path_unusable",
			"user", user.Email, "device", device.ID, "device_id", device.DeviceID, "detail", v.reason)
		http.Redirect(w, r, dest+"?error="+url.QueryEscape(
			op+" refused: "+v.reason+". Tick accept serial recovery to "+op+" anyway"),
			http.StatusFound)
		return v, false, false
	}
	accepted := serialRecoveryAccepted(paired, v, override)
	if accepted {
		slog.Warn("device."+op+".serial_recovery_accepted",
			"user", user.Email, "device", device.ID, "device_id", device.DeviceID, "detail", v.reason)
	}
	return v, accepted, true
}

// auditDetail marks an audit row when the override did the work.
// in: base detail, accepted. out: detail.
func auditDetail(detail map[string]any, accepted bool) map[string]any {
	if accepted {
		detail["serial_recovery_accepted"] = true
	}
	return detail
}

// auditTimeout bounds one audit write after a committed mutation: the row
// must outlive the request, not a database outage.
const auditTimeout = 10 * time.Second

// preemptiveCertClear walks an online paired device through a hands-off
// recovery state before the delete cascade revokes broker-side state.
// Three MQTT-CLI publishes in order, spaced so the firmware's single-slot
// deferred-CLI handler can process each before the next arrives:
//
//  1. config.set mqtt.port 8883 - flips the device from the mTLS listener
//     port (which requires a client cert) back to the password listener
//     port. Without this, the device on reboot would try TLS on 8884
//     with no cert and hit "broker requires client_cert" on every retry.
//  2. cert.clear                - wipes the now-revoked client cert from
//     NVS so the next connect attempt uses password auth via the global
//     `mqtt` dynsec user (whose ACL is independent of per-device roles
//     about to be dropped). That user may be disabled at the broker, in
//     which case recovery strands the device until it is re-enabled.
//  3. restart                   - forces a reboot. Without this, the
//     existing TLS session may stay alive even after broker-side revoke
//     because mosquitto does not actively kick clients on dynsec
//     teardown. With restart, the device cycles in ~10 s and lands
//     ready to re-pair through the normal admin UI flow.
//
// Best-effort throughout. If the device is offline or any publish fails,
// each step logs and the cascade continues - the existing manual
// recovery path (operator runs cert.clear + config.set port over serial)
// still applies. Total added latency ~2 s per device.
//
// Verified end-to-end 2026-04-30 against sht31: without step 1 + 3 the
// device stranded on the mTLS port post-delete and required serial
// access to flip the port back; with all three steps the recovery is
// fully hands-off.
//
// pub() substitutes "{}" for any empty payload because SIM7080G modem-
// native MQTT silently drops +SMSUB: URCs for zero-length payloads on
// firmware revision 1951B17 and other pre-LR8.02 revisions. Parent fw
// cli handler ignores payload content for no-arg commands (cert.clear,
// restart), so the substitution is fully backward-compatible with the
// WiFi side.
//
// in: ctx, server, device pointer (only MQTTTopicPrefix is used), op
// label for slog ("device delete" / "bulk delete"), recovery path usable
// (from recoveryPath; the caller already passed destructiveAllowed). out: none.
func preemptiveCertClear(ctx context.Context, s *Server, device *service.Device, op string, usable bool) {
	if device.MQTTTopicPrefix == nil || *device.MQTTTopicPrefix == "" {
		return
	}
	prefix := *device.MQTTTopicPrefix

	// The sequence below hands the device to the shared fallback credential.
	// With that credential unusable, step 2 would wipe the only cert the
	// device has and step 3 reboot it into a broker that refuses it. The
	// operator accepted serial recovery to get here; do not make it worse.
	if !usable {
		slog.Warn(op+": pre-emptive cert clear skipped, fallback credential unusable",
			"device", device.ID, "fallback_user", s.cfg.MQTTDeviceFallbackUser)
		return
	}

	pub := func(cmd string, payload string) bool {
		topic := mqtt.CLICommandTopic(prefix, cmd)
		body := []byte(payload)
		if len(body) == 0 {
			body = []byte("{}")
		}
		if perr := s.mqtt.PublishRaw(topic, body, 0, false); perr != nil {
			slog.Warn(op+": pre-emptive "+cmd+" publish failed",
				"device", device.ID, "topic", topic, "err", perr)
			return false
		}
		slog.Info(op+": pre-emptive "+cmd+" published",
			"device", device.ID, "topic", topic)
		return true
	}

	// Spacing between publishes - the firmware's MQTT CLI deferred ring is
	// single-slot, so back-to-back publishes risk the second one being
	// dropped with "CLI busy". 600 ms covers config.set's save+reload path
	// comfortably and is well under any keepalive horizon.
	step := func() {
		select {
		case <-time.After(600 * time.Millisecond):
		case <-ctx.Done():
		}
	}

	// Each step is a precondition for the next, so a failed publish stops the
	// sequence. Clearing the cert after the port flip did not land leaves the
	// device dialling the mTLS listener with nothing to present.
	// Step 1: flip MQTT port from the mTLS listener back to password
	if !pub("config.set", fmt.Sprintf("mqtt.port %d", mqttPortPassword)) {
		slog.Warn(op+": pre-emptive sequence aborted at port flip",
			"device", device.ID)
		return
	}
	step()
	// Step 2: clear NVS client cert
	if !pub("cert.clear", "") {
		slog.Warn(op+": pre-emptive sequence aborted at cert clear",
			"device", device.ID)
		return
	}
	step()
	// Step 3: force reboot so the new port + missing cert take effect
	pub("restart", "")
	// Slightly longer wait after restart so the firmware's response
	// publishes before the cascade starts revoking broker-side state.
	select {
	case <-time.After(800 * time.Millisecond):
	case <-ctx.Done():
	}
}

// cascadeVerdict is the outcome of one bulk cascade.
type cascadeVerdict int

const (
	cascadeOK       cascadeVerdict = iota
	cascadeOKSealed                // deleted, but the enrollment rows may still be sealed
	cascadeRefused                 // recovery gate, nothing touched
	cascadeFailed                  // revoke or DB delete failed
)

// cascadeDeleteOne gates, revokes, tears down dynsec and cascades the DB row
// for one device; everything after the committed revoke ignores request
// cancellation. Mirrors handleAdminDeviceDelete minus the confirm gate.
// in: ctx, operator email, device, probe verdict, operator override. out: verdict.
func (s *Server) cascadeDeleteOne(ctx context.Context, opEmail string, device *service.Device, v recoveryVerdict, override bool) cascadeVerdict {
	paired := device.PairedAt != nil
	if !destructiveAllowed(paired, v.usable, override) {
		slog.Warn("device.delete.refused", "reason", "recovery_path_unusable",
			"user", opEmail, "device", device.ID, "device_id", device.DeviceID, "detail", v.reason, "bulk", true)
		return cascadeRefused
	}
	if serialRecoveryAccepted(paired, v, override) {
		slog.Warn("device.delete.serial_recovery_accepted",
			"user", opEmail, "device", device.ID, "device_id", device.DeviceID, "detail", v.reason, "bulk", true)
	}
	preemptiveCertClear(ctx, s, device, "bulk delete", v.usable)

	if err := s.services.Certificates.Revoke(ctx, device.TenantID, device.ID); err != nil {
		slog.Error("bulk delete: revoke cert failed",
			"user", opEmail, "device", device.ID, "err", err)
		return cascadeFailed
	}
	ctx = context.WithoutCancel(ctx)
	if device.PairedAt != nil {
		logPairStateChange(device, "paired", "revoked", opEmail, "bulk_delete")
	}

	cn := service.DeviceCertCN(device.TenantID, device.DeviceID)
	roleName := dynsecDeviceRoleName(device.TenantID, device.DeviceID)
	dynsecCtx, dynsecCancel := context.WithTimeout(ctx, 10*time.Second)
	defer dynsecCancel()
	if derr := s.mqtt.DeleteDynsecClient(dynsecCtx, cn); derr != nil {
		slog.Warn("bulk delete: dynsec deleteClient failed",
			"device", device.ID, "cn", cn, "err", derr)
	}
	if derr := s.mqtt.DeleteDynsecRole(dynsecCtx, roleName); derr != nil {
		slog.Warn("bulk delete: dynsec deleteRole failed",
			"device", device.ID, "role", roleName, "err", derr)
	}

	// Clear retained MQTT topics owned by this device.
	// Best-effort, identical semantics to the single-device path.
	if device.MQTTTopicPrefix != nil && *device.MQTTTopicPrefix != "" {
		retCtx, retCancel := context.WithTimeout(ctx, 10*time.Second)
		cleared, failed, rerr := s.mqtt.ClearDeviceRetained(retCtx, *device.MQTTTopicPrefix)
		retCancel()
		if rerr != nil {
			slog.Warn("bulk delete: clear retained skipped",
				"device", device.ID, "topic_prefix", *device.MQTTTopicPrefix, "err", rerr)
		} else {
			slog.Info("bulk delete: cleared retained topics",
				"device", device.ID, "topic_prefix", *device.MQTTTopicPrefix,
				"cleared", cleared, "failed", failed)
		}
	} else {
		// See admin_device_delete.go for rationale - keep the new code
		// path observable on devices that never published an info message.
		slog.Info("bulk delete: clear retained skipped (no topic_prefix)",
			"device", device.ID, "device_id", device.DeviceID)
	}

	dbCtx, dbCancel := context.WithTimeout(ctx, 30*time.Second)
	defer dbCancel()
	if err := s.services.Devices.DeleteByID(dbCtx, device.TenantID, device.ID); err != nil {
		slog.Error("bulk delete: DB delete failed",
			"user", opEmail, "device", device.ID, "err", err)
		return cascadeFailed
	}
	enrollErr := s.resetDeviceEnrollment(ctx, device.DeviceID, "bulk delete")

	tombPrefix := ""
	if device.MQTTTopicPrefix != nil {
		tombPrefix = *device.MQTTTopicPrefix
	}
	tombCtx, tombCancel := context.WithTimeout(ctx, 10*time.Second)
	defer tombCancel()
	if terr := s.services.Devices.Tombstone(tombCtx, device.TenantID, device.DeviceID, tombPrefix); terr != nil {
		slog.Warn("bulk delete: tombstone write failed",
			"device", device.ID, "tenant", device.TenantID, "device_id", device.DeviceID, "err", terr)
	}
	slog.Info("device deleted (bulk)",
		"user", opEmail, "device", device.DeviceID, "tenant", device.TenantID, "pk", device.ID)
	if enrollErr != nil {
		return cascadeOKSealed
	}
	return cascadeOK
}
