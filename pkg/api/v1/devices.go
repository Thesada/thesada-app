// JSON device-read handlers for /api/v1/devices*: list, get, telemetry, alerts.
// All are RequireAuthJSON-gated and tenant-scoped via authmw.EffectiveTenantID;
// the per-device routes resolve the device through the tenant-scoped GetByID so
// a caller can only reach their own tenant's devices.
package v1

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service"
)

// deviceResponse is the redacted device shape returned by the API - omits the
// pairing key, owner id, tenant id (implicit), and mqtt topic prefix.
type deviceResponse struct {
	ID                uuid.UUID  `json:"id"`
	DeviceID          string     `json:"device_id"`
	DisplayName       *string    `json:"display_name"`
	HardwareType      *string    `json:"hardware_type"`
	FirmwareVersion   *string    `json:"firmware_version"`
	PairedAt          *time.Time `json:"paired_at"`
	LastSeenAt        *time.Time `json:"last_seen_at"`
	CreatedAt         time.Time  `json:"created_at"`
	LastUptimeSeconds *int64     `json:"last_uptime_seconds,omitempty"`
	LastUptimeAt      *time.Time `json:"last_uptime_at,omitempty"`
}

// telemetryPoint is a single telemetry reading (raw payload omitted).
type telemetryPoint struct {
	Metric     string    `json:"metric"`
	ReceivedAt time.Time `json:"received_at"`
	ValueNum   *float64  `json:"value_num"`
	ValueText  *string   `json:"value_text"`
}

// alertResponse is a single device alert (raw payload + device pk omitted).
type alertResponse struct {
	ID                int64     `json:"id"`
	ReceivedAt        time.Time `json:"received_at"`
	Severity          string    `json:"severity"`
	Code              *string   `json:"code"`
	Message           string    `json:"message"`
	DeliveredEmail    bool      `json:"delivered_email"`
	DeliveredTelegram bool      `json:"delivered_telegram"`
}

// toDeviceResponse maps a service.Device to its redacted API shape.
// in: *service.Device. out: deviceResponse.
func toDeviceResponse(d *service.Device) deviceResponse {
	return deviceResponse{
		ID:                d.ID,
		DeviceID:          d.DeviceID,
		DisplayName:       d.DisplayName,
		HardwareType:      d.HardwareType,
		FirmwareVersion:   d.FirmwareVersion,
		PairedAt:          d.PairedAt,
		LastSeenAt:        d.LastSeenAt,
		CreatedAt:         d.CreatedAt,
		LastUptimeSeconds: d.LastUptimeSeconds,
		LastUptimeAt:      d.LastUptimeAt,
	}
}

// queryInt reads a positive ?name= int, clamped to [1,max], falling back to def
// when absent or unparseable. Used to bound list-size query params.
// in: request, param name, default, max. out: clamped int.
func queryInt(r *http.Request, name string, def, max int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// resolveDevice parses {id}, looks the device up scoped to the caller's tenant,
// and writes a 400/404/500 + returns nil on failure. A non-nil return means the
// device exists and belongs to the caller's tenant.
// in: writer, request. out: *service.Device or nil (response already written).
func (s *Server) resolveDevice(w http.ResponseWriter, r *http.Request) *service.Device {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad device id"})
		return nil
	}
	tenant := authmw.EffectiveTenantID(r)
	d, err := s.services.Devices.GetByID(id, tenant)
	if err != nil {
		slog.Error("api device lookup failed", "id", id, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "lookup failed"})
		return nil
	}
	if d == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
		return nil
	}
	return d
}

// handleDeviceList returns the caller tenant's devices.
// in: writer, GET /devices. out: 200 []deviceResponse.
func (s *Server) handleDeviceList(w http.ResponseWriter, r *http.Request) {
	tenant := authmw.EffectiveTenantID(r)
	devices, err := s.services.Devices.ListByTenant(tenant)
	if err != nil {
		slog.Error("api device list failed", "tenant", tenant, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "list failed"})
		return
	}
	out := make([]deviceResponse, 0, len(devices))
	for i := range devices {
		out = append(out, toDeviceResponse(&devices[i]))
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeviceGet returns one device by id (tenant-scoped).
// in: writer, GET /devices/{id}. out: 200 deviceResponse / 400 / 404.
func (s *Server) handleDeviceGet(w http.ResponseWriter, r *http.Request) {
	d := s.resolveDevice(w, r)
	if d == nil {
		return
	}
	writeJSON(w, http.StatusOK, toDeviceResponse(d))
}

// handleDeviceTelemetry returns telemetry for a device: the latest reading per
// metric by default, or the recent N readings of a single metric when ?metric=
// is given (?limit= clamps, default 100, max 500).
// in: writer, GET /devices/{id}/telemetry. out: 200 []telemetryPoint / 400 / 404.
func (s *Server) handleDeviceTelemetry(w http.ResponseWriter, r *http.Request) {
	d := s.resolveDevice(w, r)
	if d == nil {
		return
	}
	ctx := r.Context()
	out := make([]telemetryPoint, 0)
	if metric := r.URL.Query().Get("metric"); metric != "" {
		rows, err := s.services.Telemetry.RecentTelemetry(ctx, d.TenantID, d.ID, metric, queryInt(r, "limit", 100, 500))
		if err != nil {
			slog.Error("api telemetry failed", "device", d.ID, "metric", metric, "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "telemetry failed"})
			return
		}
		for i := range rows {
			out = append(out, telemetryPoint{Metric: rows[i].Metric, ReceivedAt: rows[i].ReceivedAt, ValueNum: rows[i].ValueNum, ValueText: rows[i].ValueText})
		}
	} else {
		rows, err := s.services.Telemetry.LatestPerMetric(ctx, d.TenantID, d.ID)
		if err != nil {
			slog.Error("api telemetry latest failed", "device", d.ID, "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "telemetry failed"})
			return
		}
		for i := range rows {
			out = append(out, telemetryPoint{Metric: rows[i].Metric, ReceivedAt: rows[i].ReceivedAt, ValueNum: rows[i].ValueNum, ValueText: rows[i].ValueText})
		}
	}
	writeJSON(w, http.StatusOK, out)
}

// handleDeviceAlerts returns recent alerts for a device, newest first. Optional
// ?severity= filter and ?limit= (default 100, max 500).
// in: writer, GET /devices/{id}/alerts. out: 200 []alertResponse / 400 / 404.
func (s *Server) handleDeviceAlerts(w http.ResponseWriter, r *http.Request) {
	d := s.resolveDevice(w, r)
	if d == nil {
		return
	}
	rows, err := s.services.Alerts.RecentAlerts(r.Context(), d.TenantID, d.ID, r.URL.Query().Get("severity"), queryInt(r, "limit", 100, 500))
	if err != nil {
		slog.Error("api device alerts failed", "device", d.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "alerts failed"})
		return
	}
	out := make([]alertResponse, 0, len(rows))
	for i := range rows {
		out = append(out, alertResponse{
			ID:                rows[i].ID,
			ReceivedAt:        rows[i].ReceivedAt,
			Severity:          rows[i].Severity,
			Code:              rows[i].Code,
			Message:           rows[i].Message,
			DeliveredEmail:    rows[i].DeliveredEmail,
			DeliveredTelegram: rows[i].DeliveredTelegram,
		})
	}
	writeJSON(w, http.StatusOK, out)
}
