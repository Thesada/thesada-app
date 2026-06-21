// Single-device delete on /admin/devices/{id}/delete.
// PR 1: cert revoke + dynsec teardown + DB cascade.
// PR 3: retained-topics clear via the firmware manifest.
// Bulk wrapper + cross-tenant gate live in admin_devices_bulk.go (PR 2).
package web

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
)

// handleAdminDeviceDelete tears down a device end-to-end:
//
//  1. Confirmation gate: form must include `confirm_device_id` matching the
//     device's device_id. Prevents misclicks. Server-side check; the client
//     also asks via confirm() for the wide-net "are you sure" prompt.
//  2. Certificates.Revoke first - flips revoked_at so the cert audit row
//     reflects the revoke event before the FK CASCADE wipes it.
//  3. dynsec teardown (best-effort) - DeleteDynsecClient + DeleteDynsecRole.
//     Failures logged but do not block the delete since the cert is already
//     revoked; the broker rejects the device on next auth check regardless.
//  4. DELETE FROM devices (load-bearing) - the FK CASCADE handles every
//     dependent table.
//
// Retained MQTT topic clear (PR 3) consumes the firmware-published manifest
// at <prefix>/info/retained_topics. Runs after dynsec teardown
// so the device cannot republish the manifest mid-clear. Best-effort: a
// missing manifest (e.g. app restarted after the device last published) is
// logged and the delete proceeds - the broker keeps stale retained payloads
// that the operator can clean up out of band.
//
// in: writer, POST /admin/devices/{id}/delete with confirm_device_id form
// field. out: 302 to /admin/devices.
func (s *Server) handleAdminDeviceDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil || device == nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.PostFormValue("confirm_device_id") != device.DeviceID {
		http.Redirect(w, r,
			"/admin/devices?error=confirm+device_id+did+not+match",
			http.StatusFound)
		return
	}

	user := authmw.CurrentUser(r)

	// Step 0: walk an online paired device through hands-off recovery
	// before the cascade revokes broker-side state. Sends three MQTT CLI
	// commands (config.set mqtt.port 8883, cert.clear, restart) so the
	// device reboots back onto the password-auth port with no NVS cert,
	// ready to re-pair through the normal admin UI flow. See
	// preemptiveCertClear in admin_devices_bulk.go for the full rationale
	// + ordering verified against sht31 on 2026-04-30.
	preemptiveCertClear(r.Context(), s, device, "device delete")

	// Step 1: revoke cert. Load-bearing - if revoke fails we abort because
	// the audit trail must reflect "operator chose to delete this" before
	// the row vanishes.
	if err := s.services.Certificates.Revoke(r.Context(), device.TenantID, device.ID); err != nil {
		slog.Error("device delete: revoke cert failed",
			"user", user.Email, "device", device.ID, "err", err)
		http.Redirect(w, r, "/admin/devices?error=revoke+failed", http.StatusFound)
		return
	}
	if device.PairedAt != nil {
		logPairStateChange(device, "paired", "revoked", user.Email, "device_delete")
	}

	// Step 2: dynsec teardown. Best-effort. Bound the time we wait so a
	// broker outage can't pin the request handler.
	cn := fmt.Sprintf("thesada-%s-%s", device.TenantID, device.DeviceID)
	roleName := dynsecDeviceRoleName(device.TenantID, device.DeviceID)
	dynsecCtx, dynsecCancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer dynsecCancel()
	if derr := s.mqtt.DeleteDynsecClient(dynsecCtx, cn); derr != nil {
		slog.Warn("device delete: dynsec deleteClient failed",
			"device", device.ID, "cn", cn, "err", derr)
	}
	if derr := s.mqtt.DeleteDynsecRole(dynsecCtx, roleName); derr != nil {
		slog.Warn("device delete: dynsec deleteRole failed",
			"device", device.ID, "role", roleName, "err", derr)
	}

	// Step 3: clear retained MQTT topics owned by this device.
	// Best-effort, logged. Reads cached manifest from the firmware
	// <prefix>/info/retained_topics topic. Do this after dynsec
	// teardown so the device cannot reconnect and republish mid-clear.
	if device.MQTTTopicPrefix != nil && *device.MQTTTopicPrefix != "" {
		retCtx, retCancel := context.WithTimeout(r.Context(), 10*time.Second)
		cleared, failed, rerr := s.mqtt.ClearDeviceRetained(retCtx, *device.MQTTTopicPrefix)
		retCancel()
		if rerr != nil {
			slog.Warn("device delete: clear retained skipped",
				"device", device.ID, "topic_prefix", *device.MQTTTopicPrefix, "err", rerr)
		} else {
			slog.Info("device delete: cleared retained topics",
				"device", device.ID, "topic_prefix", *device.MQTTTopicPrefix,
				"cleared", cleared, "failed", failed)
		}
	} else {
		// Device row has no topic_prefix recorded - the device never published
		// an `<prefix>/info` message that handleInfo could ingest. Log so the
		// retained-clear path is observable from journalctl even when there
		// is nothing to clear (otherwise the delete looks identical to the
		// pre-PR-3 flow on these devices and the operator cannot tell from
		// logs whether the new code path actually ran).
		slog.Info("device delete: clear retained skipped (no topic_prefix)",
			"device", device.ID, "device_id", device.DeviceID)
	}

	// Step 4: DELETE FROM devices. FK CASCADE handles dependents.
	dbCtx, dbCancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer dbCancel()
	if err := s.services.Devices.DeleteByID(dbCtx, device.TenantID, device.ID); err != nil {
		slog.Error("device delete: DB delete failed",
			"user", user.Email, "device", device.ID, "err", err)
		http.Redirect(w, r, "/admin/devices?error=db+delete+failed", http.StatusFound)
		return
	}

	// Step 5: tombstone. Records the (tenant, device, prefix)
	// so the MQTT ingest path drops retained replays at next app restart
	// instead of recreating the device row from broker-side ghosts. No-op
	// when the device row never carried a topic prefix.
	tombPrefix := ""
	if device.MQTTTopicPrefix != nil {
		tombPrefix = *device.MQTTTopicPrefix
	}
	if terr := s.services.Devices.Tombstone(r.Context(), device.TenantID, device.DeviceID, tombPrefix); terr != nil {
		slog.Warn("device delete: tombstone write failed",
			"device", device.ID, "tenant", device.TenantID, "device_id", device.DeviceID, "err", terr)
	}

	slog.Info("device deleted",
		"user", user.Email, "device", device.DeviceID, "tenant", device.TenantID, "pk", device.ID)

	http.Redirect(w, r,
		"/admin/devices?ok=deleted+"+device.DeviceID,
		http.StatusFound)
}
