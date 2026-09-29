package web

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/authz"
	"thesada.app/app/pkg/service"
)

// handleDeviceList renders the tenant device table from a live DB query.
// in: writer, request. out: HTML table or empty-state.
func (s *Server) handleDeviceList(w http.ResponseWriter, r *http.Request) {
	tenantID := authmw.EffectiveTenantID(r)
	devices, err := s.services.Devices.ListByTenant(tenantID)
	if err != nil {
		slog.Error("device list failed", "err", err)
		http.Error(w, "device list failed", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "devices.html", map[string]interface{}{"Devices": devices})
}

// deviceInScope is the one tenant-scope rule for /devices/{id} handlers:
// cross only when crossTenant is granted, else the effective tenant.
// in: request, device pk, action that grants cross-tenant. out: device or nil, error.
func (s *Server) deviceInScope(r *http.Request, id uuid.UUID, crossTenant authz.Action) (*service.Device, error) {
	if authz.Can(authmw.CurrentUser(r), crossTenant) {
		return s.services.Devices.GetByIDAny(r.Context(), id)
	}
	return s.services.Devices.GetByID(id, authmw.EffectiveTenantID(r))
}

// handleDeviceDetail renders one device with its recent heartbeats and alerts.
// in: writer, request with path value "id" (UUID). out: HTML page or 404.
func (s *Server) handleDeviceDetail(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	me := authmw.CurrentUser(r)
	device, err := s.deviceInScope(r, id, authz.DeviceReadCrossTenant)
	if err != nil {
		slog.Error("device get failed", "id", id, "err", err)
		http.Error(w, "device get failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}
	latest, err := s.services.Telemetry.LatestPerMetric(r.Context(), device.TenantID, id)
	if err != nil {
		slog.Error("latest sensors fetch failed", "id", id, "err", err)
		http.Error(w, "sensors fetch failed", http.StatusInternalServerError)
		return
	}
	telemetry, err := s.services.Telemetry.RecentTelemetry(r.Context(), device.TenantID, id, "", 50)
	if err != nil {
		slog.Error("telemetry fetch failed", "id", id, "err", err)
		http.Error(w, "telemetry fetch failed", http.StatusInternalServerError)
		return
	}
	alerts, err := s.services.Alerts.RecentAlerts(r.Context(), device.TenantID, id, "", 25)
	if err != nil {
		slog.Error("alerts fetch failed", "id", id, "err", err)
		http.Error(w, "alerts fetch failed", http.StatusInternalServerError)
		return
	}
	// Build a sorted list of numeric metric names for the chart selector.
	// A metric is "numeric" if its latest row has a non-null value_num.
	// Text metrics (battery/charging, wifi/ip, etc) are skipped - caggs
	// exclude them and the chart has nothing to show.
	numericMetrics := make([]string, 0, len(latest))
	for _, t := range latest {
		if t.ValueNum != nil {
			numericMetrics = append(numericMetrics, t.Metric)
		}
	}
	sort.Strings(numericMetrics)

	// The revoke card sits outside #device-live, so HTMX refreshes skip the
	// audited claim read. The card is only an offer; the POST re-checks, so a
	// failed read hides it instead of failing the page.
	canRevoke := false
	if r.Header.Get("HX-Request") != "true" {
		verdict, err := s.revokeCheck(r.Context(), me, device)
		if err != nil {
			slog.Warn("device.revoke.check_failed", "id", id, "err", err)
		} else {
			canRevoke = verdict == revokeAllowed
		}
	}
	flash, flashErr := deviceFlash(r.URL.Query())

	// If a super-admin landed here from /admin/devices, send the back link
	// there instead of the tenant-scoped /devices list. Avoids the
	// "Admin -> Devices -> click a row -> back -> wrong page" surprise.
	backHref := "/devices"
	backLabel := "All devices"
	if authz.Can(authmw.CurrentUser(r), authz.DeviceReadCrossTenant) {
		ref := r.Referer()
		if strings.Contains(ref, "/admin/devices") && !strings.Contains(ref, "/admin/devices/") {
			backHref = "/admin/devices"
			backLabel = "Admin devices"
		}
	}

	s.render(w, r, "device-detail.html", map[string]interface{}{
		"Device":         device,
		"Latest":         latest,
		"Telemetry":      telemetry,
		"Alerts":         alerts,
		"NumericMetrics": numericMetrics,
		"BackHref":       backHref,
		"BackLabel":      backLabel,
		"CanRevoke":      canRevoke,
		"Flash":          flash,
		"FlashErr":       flashErr,
	})
}

// handleDeviceChartJSON returns a bucketed time-series for one metric on
// one device in JSON form. Used by the Chart.js client on device-detail.
// Tenant-scoped via EffectiveTenantID so a super-admin impersonating a
// different tenant cannot read another tenant's history.
// in: writer, request (path {id}, query metric, range). out: JSON series.
func (s *Server) handleDeviceChartJSON(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	device, err := s.deviceInScope(r, id, authz.DeviceReadCrossTenant)
	if err != nil {
		slog.Error("chart device get failed", "id", id, "err", err)
		http.Error(w, "device get failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}
	metric := r.URL.Query().Get("metric")
	rangeName := r.URL.Query().Get("range")
	if rangeName == "" {
		rangeName = "24h"
	}
	series, err := s.services.Telemetry.History(r.Context(), device.TenantID, id, metric, rangeName)
	if err != nil {
		if errors.Is(err, service.ErrInvalidRange) {
			http.Error(w, "invalid range or metric", http.StatusBadRequest)
			return
		}
		slog.Error("chart history fetch failed", "id", id, "metric", metric, "range", rangeName, "err", err)
		http.Error(w, "history fetch failed", http.StatusInternalServerError)
		return
	}
	// Shape for Chart.js: parallel arrays keep the JS side small.
	labels := make([]string, 0, len(series.Points))
	avg := make([]*float64, 0, len(series.Points))
	minV := make([]*float64, 0, len(series.Points))
	maxV := make([]*float64, 0, len(series.Points))
	for _, p := range series.Points {
		labels = append(labels, p.T.UTC().Format(time.RFC3339))
		avg = append(avg, p.Avg)
		minV = append(minV, p.Min)
		maxV = append(maxV, p.Max)
	}
	resp := map[string]interface{}{
		"metric": series.Metric,
		"range":  series.Range,
		"labels": labels,
		"avg":    avg,
		"min":    minV,
		"max":    maxV,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("chart json encode failed", "err", err)
	}
}
