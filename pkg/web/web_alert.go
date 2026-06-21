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
	s.render(w, r, "alerts.html", map[string]interface{}{"Alerts": rows})
}
