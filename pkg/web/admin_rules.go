package web

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"
)

func (s *Server) handleAdminDeviceRules(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
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

	s.render(w, r, "admin-device-rules.html", map[string]interface{}{
		"Device":            device,
		"TopicPrefix":       s.deviceTopicPrefix(device),
		"CLITimeoutSeconds": int(s.cfg.CLIRequestTimeout.Seconds()),
	})
}
