// Per-sensor telemetry delete on /devices/{id}/sensors/delete.
// Cleans up the stale-after-rename row that lingers when a OneWire sensor is
// replaced / reassigned: device-side firmware stops publishing under the old
// metric name, but the existing telemetry rows + LatestPerMetric snapshot keep
// it visible on the device-detail page indefinitely.
//
// Tenant-scoped: the device must belong to the requesting user's effective
// tenant, OR the user must be a super-admin (consistent with handleDeviceDetail).
//
// HA discovery retained-topic clear is intentionally NOT included in this PR.
// The retained-topics manifest lists every topic the device owns but does not
// expose the metric -> uid mapping HA discovery uses, so any glob-match would
// either over-clear (wipe sibling sensors with similar names) or under-clear
// (miss uid suffixes the firmware picked). Operator can clear stale HA
// discovery via mosquitto in the meantime; a follow-up issue will track the
// proper firmware-side metric -> retained-topic affinity that lets the app
// scope the clear safely.
package web

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service"
)

// handleDeviceSensorDelete deletes every device_telemetry row for one
// (device_pk, metric) tuple. metric arrives in the form body so it can carry
// arbitrary characters (slashes, dots) without URL path encoding ambiguity.
//
// in: writer, POST /devices/{id}/sensors/delete with form fields
//
//	metric=<full metric name> + confirm_metric=<same value>.
//
// out: 302 to /devices/{id} with ok= or error= flash.
func (s *Server) handleDeviceSensorDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	metric := strings.TrimSpace(r.PostFormValue("metric"))
	if metric == "" {
		http.Redirect(w, r,
			"/devices/"+id.String()+"?error=metric+required",
			http.StatusFound)
		return
	}
	if r.PostFormValue("confirm_metric") != metric {
		http.Redirect(w, r,
			"/devices/"+id.String()+"?error=confirm+metric+did+not+match",
			http.StatusFound)
		return
	}

	// Tenant scope - mirror handleDeviceDetail.
	me := authmw.CurrentUser(r)
	var device *service.Device
	if me != nil && me.IsSuperAdmin {
		device, err = s.services.Devices.GetByIDAny(r.Context(), id)
	} else {
		device, err = s.services.Devices.GetByID(id, authmw.EffectiveTenantID(r))
	}
	if err != nil {
		slog.Error("sensor delete: device get failed", "id", id, "err", err)
		http.Error(w, "device get failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}

	count, err := s.services.Telemetry.DeleteSensorTelemetry(r.Context(), device.TenantID, device.ID, metric)
	if err != nil {
		slog.Error("sensor delete: db delete failed",
			"user", me.Email, "device", device.ID, "metric", metric, "err", err)
		http.Redirect(w, r,
			"/devices/"+id.String()+"?error=delete+failed",
			http.StatusFound)
		return
	}

	slog.Info("sensor telemetry deleted",
		"user", me.Email, "device", device.DeviceID, "tenant", device.TenantID,
		"metric", metric, "rows", count)

	http.Redirect(w, r,
		"/devices/"+id.String()+"?ok=cleared+"+metric,
		http.StatusFound)
}
