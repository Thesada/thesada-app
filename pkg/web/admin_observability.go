// Super-admin observability page: GET /admin/observability renders the
// DB-derived platform health snapshot (waitlist funnel, alert delivery
// lifecycle, device fleet + cert lifecycle, audit activity). No metrics
// infrastructure behind it - every number is an aggregate the
// ObservabilityService reads from tables the app already maintains.
// Assumes the authmw.RequireSuperAdmin wrap.
package web

import (
	"log/slog"
	"net/http"
)

// handleAdminObservability renders the platform-health snapshot page.
// in: writer, GET /admin/observability. out: HTML page.
func (s *Server) handleAdminObservability(w http.ResponseWriter, r *http.Request) {
	stats, err := s.services.Observability.Snapshot(r.Context())
	if err != nil {
		slog.Error("admin observability snapshot failed", "err", err)
		http.Error(w, "snapshot failed", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "admin-observability.html", map[string]interface{}{
		"Stats": stats,
	})
}
