package web

import (
	"log/slog"
	"net/http"

	"thesada.app/app/pkg/authmw"
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
	s.render(w, r, "alerts.html", map[string]interface{}{
		"Alerts":       rows,
		"TrendRules":   rules,
		"TrendMetrics": metrics,
		"Devices":      devices,
		"SavedSection": r.URL.Query().Get("saved"),
		"ErrSection":   r.URL.Query().Get("err"),
	})
}
