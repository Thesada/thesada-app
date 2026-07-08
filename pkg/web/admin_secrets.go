// Super-admin write-only device-config-secrets UI (#443 phase 6). The
// operator sets/overwrites the encrypted secrets; the page shows only
// set/unset status per field and NEVER a value. There is no read-back path -
// SecretService.Reveal is server-side-only (provision/rotate) and is
// deliberately not wired to any handler here. All handlers assume the
// authmw.RequireSuperAdmin wrap.
package web

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service"
)

// secretInfoTimeout bounds the live secret.info round-trip so an offline
// device never hangs the secrets page - it just renders device state unknown.
const secretInfoTimeout = 5 * time.Second

// secretFieldStatus is one row of the write-only form: the storage field, its
// app-store set/unset state, and the live device NVS state ("nvs", "config",
// "none", or "" when the device was unreachable). The value is never carried.
type secretFieldStatus struct {
	Field    string
	Set      bool
	DevState string
}

// parseSecretInfo turns firmware `secret.info` output into a map of firmware
// field key -> state token. Each line is "<field>  <state>" (e.g.
// "mqtt.password nvs", "wifi.password:HomeNet config/none"); the state is the
// last whitespace-separated token, normalized to "nvs" or "config".
// in: output lines. out: map[fwField]state.
func parseSecretInfo(output []string) map[string]string {
	states := make(map[string]string, len(output))
	for _, line := range output {
		toks := strings.Fields(line)
		if len(toks) < 2 {
			continue
		}
		field := toks[0]
		state := toks[len(toks)-1]
		if strings.HasPrefix(state, "nvs") {
			states[field] = "nvs"
		} else {
			states[field] = "config"
		}
	}
	return states
}

// deviceSecretState queries the device over MQTT for its live per-field NVS
// state, keyed by storage field. Bounded by secretInfoTimeout; a timeout or
// error yields (nil, false) and the page renders state unknown rather than
// failing. in: ctx, device, wifi ssid. out: map[storageField]state, reachable.
func (s *Server) deviceSecretState(ctx context.Context, device *service.Device, ssid string) (map[string]string, bool) {
	if s.mqtt == nil {
		return nil, false
	}
	cctx, cancel := context.WithTimeout(ctx, secretInfoTimeout)
	defer cancel()
	resp, err := s.mqtt.CLIRequest(cctx, s.deviceTopicPrefix(device), "secret.info", "")
	if err != nil || resp == nil || !resp.OK {
		return nil, false
	}
	byFwField := parseSecretInfo(resp.Output)
	out := make(map[string]string, len(service.SecretFields))
	for _, f := range service.SecretFields {
		fwField, ok := service.FirmwareSecretField(f, ssid)
		if !ok {
			continue // wifi.password with no known SSID - cannot match a device key
		}
		if st, present := byFwField[fwField]; present {
			out[f] = st
		} else {
			out[f] = "none"
		}
	}
	return out, true
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
	if err != nil {
		// A real backend error must not masquerade as 404 (AGENTS.md: fail loud).
		slog.Error("device lookup failed", "device", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
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
	// Live device NVS state per field (best-effort; empty when unreachable).
	// Only queried with the feature on - a KEK-off deployment never provisions.
	var devState map[string]string
	reachable := false
	if s.services.Secrets.Enabled() {
		ssid := s.deviceWifiSSID(r.Context(), device)
		devState, reachable = s.deviceSecretState(r.Context(), device, ssid)
	}

	// Drive display order from SecretFields (Status is an unordered map).
	fields := make([]secretFieldStatus, 0, len(service.SecretFields))
	for _, f := range service.SecretFields {
		fields = append(fields, secretFieldStatus{Field: f, Set: status[f], DevState: devState[f]})
	}

	s.render(w, r, "admin-device-secrets.html", map[string]interface{}{
		"Device":         device,
		"Enabled":        s.services.Secrets.Enabled(),
		"Fields":         fields,
		"DeviceReported": reachable,
		"Ok":             r.URL.Query().Get("ok"),
		"Error":          r.URL.Query().Get("error"),
	})
}

// handleAdminDeviceSecretsProvision pushes every stored secret to the device
// NVS over MQTT (the same path the pair flow uses), then PRG-redirects with a
// summary. For an already-paired device this is the action the pair flow would
// otherwise be the only source of. No value is logged.
// in: writer, POST /admin/devices/{id}/secrets/provision. out: 302 to page.
func (s *Server) handleAdminDeviceSecretsProvision(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil {
		slog.Error("device lookup failed", "device", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}
	dest := "/admin/devices/" + device.ID.String() + "/secrets"

	if !s.services.Secrets.Enabled() {
		http.Redirect(w, r, dest+"?error=secrets+disabled", http.StatusFound)
		return
	}

	topicPrefix := s.deviceTopicPrefix(device)
	ssid := s.deviceWifiSSID(r.Context(), device)
	outcome := provisionDeviceSecrets(service.SecretFields, ssid,
		func(field string) (string, bool, error) {
			return s.services.Secrets.Reveal(r.Context(), device.TenantID, device.ID, field)
		},
		func(fwField, value string) (string, bool) {
			return s.pushSecret(r.Context(), topicPrefix, fwField, value)
		},
	)

	if outcome.AbortMsg != "" {
		slog.Error("device_secret.provision aborted",
			"tenant", device.TenantID, "device", device.DeviceID, "reason", outcome.AbortMsg)
		http.Redirect(w, r, dest+"?error="+url.QueryEscape(outcome.AbortMsg), http.StatusFound)
		return
	}

	user := authmw.CurrentUser(r)
	actor := ""
	if user != nil {
		actor = user.Email
	}
	slog.Info("device_secret.state_change", "action", "provision",
		"tenant", device.TenantID, "device", device.DeviceID,
		"pushed", len(outcome.Pushed), "actor", actor)

	msg := "provisioned+" + itoa(len(outcome.Pushed))
	if len(outcome.SkippedUnset)+len(outcome.SkippedNoSSID) > 0 {
		msg += "+(skipped+" + itoa(len(outcome.SkippedUnset)+len(outcome.SkippedNoSSID)) + ")"
	}
	http.Redirect(w, r, dest+"?ok="+msg, http.StatusFound)
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
	if err != nil {
		// A real backend error must not masquerade as 404 (AGENTS.md: fail loud).
		slog.Error("device lookup failed", "device", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
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
