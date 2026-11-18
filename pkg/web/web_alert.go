package web

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service"
)

// handleAlertList renders the most recent alerts across all devices in the tenant.
// in: writer, request. out: HTML list.
func (s *Server) handleAlertList(w http.ResponseWriter, r *http.Request) {
	tenantID := authmw.EffectiveTenantID(r)
	rows, err := s.services.Alerts.RecentByTenant(r.Context(), tenantID, 100)
	if err != nil {
		slog.Error("alerts fetch failed", "err", err)
		http.Error(w, "alerts fetch failed", http.StatusInternalServerError)
		return
	}
	rules, err := s.services.Alerts.ListTrendRules(r.Context(), tenantID)
	if err != nil {
		slog.Error("alerts.load_failed", "part", "trend_rules", "tenant", tenantID, "err", err)
	}
	metrics, err := s.services.Alerts.TrendMetrics(r.Context(), tenantID)
	if err != nil {
		slog.Error("alerts.load_failed", "part", "trend_metrics", "tenant", tenantID, "err", err)
	}
	devices, err := s.services.Devices.ListByTenant(tenantID)
	if err != nil {
		slog.Error("alerts.load_failed", "part", "devices", "tenant", tenantID, "err", err)
	}
	// Rules the caller may change, and the add-form targets, by the Lua rules check.
	me := authmw.CurrentUser(r)
	canTenant := canEditTrendRule(me, tenantID, nil)
	byID := make(map[uuid.UUID]*service.Device, len(devices))
	var editDevices []service.Device
	for i := range devices {
		byID[devices[i].ID] = &devices[i]
		if canEditTrendRule(me, tenantID, &devices[i]) {
			editDevices = append(editDevices, devices[i])
		}
	}
	editRules := make(map[uuid.UUID]bool, len(rules))
	for _, rule := range rules {
		if rule.DevicePK == nil {
			editRules[rule.ID] = canTenant
		} else if d := byID[*rule.DevicePK]; d != nil {
			editRules[rule.ID] = canEditTrendRule(me, tenantID, d)
		}
	}
	s.render(w, r, "alerts.html", map[string]interface{}{
		"Alerts":        rows,
		"TrendRules":    rules,
		"TrendMetrics":  metrics,
		"Devices":       editDevices,
		"CanTenantRule": canTenant,
		"CanAddRule":    canTenant || len(editDevices) > 0,
		"EditRules":     editRules,
		"SavedSection":  r.URL.Query().Get("saved"),
		"ErrSection":    r.URL.Query().Get("err"),
		"AlertsUnheard": s.alertsUnheard(r, tenantID),
	})
}
