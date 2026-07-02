// Super-admin write-only device-config-secrets UI (#443 phase 6). The
// operator sets/overwrites the encrypted secrets; the page shows only
// set/unset status per field and NEVER a value. There is no read-back path -
// SecretService.Reveal is server-side-only (provision/rotate) and is
// deliberately not wired to any handler here. All handlers assume the
// authmw.RequireSuperAdmin wrap.
package web

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service"
)

// secretFieldStatus is one row of the write-only form: the field key and
// whether a value is currently stored. The value itself is never carried.
type secretFieldStatus struct {
	Field string
	Set   bool
}

// handleAdminDeviceSecrets renders the write-only secrets page for a device:
// a set/unset badge per field plus a blank input to set or overwrite each.
// in: writer, GET /admin/devices/{id}/secrets. out: HTML page.
func (s *Server) handleAdminDeviceSecrets(w http.ResponseWriter, r *http.Request) {
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

	// Status works even with the feature off (pure existence read); the form
	// itself is gated on Enabled so a KEK-off deployment shows a banner instead
	// of inputs that would only ever return ErrSecretsDisabled.
	status, err := s.services.Secrets.Status(r.Context(), device.TenantID, device.ID)
	if err != nil {
		slog.Error("device secrets status failed", "device", device.ID, "err", err)
		http.Error(w, "status error", http.StatusInternalServerError)
		return
	}
	// Drive display order from SecretFields (Status is an unordered map).
	fields := make([]secretFieldStatus, 0, len(service.SecretFields))
	for _, f := range service.SecretFields {
		fields = append(fields, secretFieldStatus{Field: f, Set: status[f]})
	}

	s.render(w, r, "admin-device-secrets.html", map[string]interface{}{
		"Device":  device,
		"Enabled": s.services.Secrets.Enabled(),
		"Fields":  fields,
		"Ok":      r.URL.Query().Get("ok"),
		"Error":   r.URL.Query().Get("error"),
	})
}

// handleAdminDeviceSecretsSet stores (or overwrites) one secret value, then
// PRG-redirects back to the page. The value is read from the form and passed
// straight to the encrypted store; it is never logged or echoed back.
// in: writer, POST /admin/devices/{id}/secrets/set. out: 302 to secrets page.
func (s *Server) handleAdminDeviceSecretsSet(w http.ResponseWriter, r *http.Request) {
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
	field := r.PostFormValue("field")
	value := r.PostFormValue("value")
	dest := "/admin/devices/" + device.ID.String() + "/secrets"

	if field == "" || value == "" {
		http.Redirect(w, r, dest+"?error=field+and+value+required", http.StatusFound)
		return
	}

	if err := s.services.Secrets.SetSecret(r.Context(), device.TenantID, device.ID, field, value); err != nil {
		// ErrSecretsDisabled or an unknown field (validSecretField) both land
		// here; surface a short message, never the value.
		slog.Warn("set device secret failed", "device", device.ID, "field", field, "err", err)
		http.Redirect(w, r, dest+"?error=set+failed", http.StatusFound)
		return
	}

	// Audit the security-relevant edit (field + actor, never the value).
	user := authmw.CurrentUser(r)
	actor := ""
	if user != nil {
		actor = user.Email
	}
	slog.Info("device_secret.state_change", "action", "set",
		"tenant", device.TenantID, "device", device.DeviceID, "field", field, "actor", actor)

	http.Redirect(w, r, dest+"?ok=set+"+field, http.StatusFound)
}
