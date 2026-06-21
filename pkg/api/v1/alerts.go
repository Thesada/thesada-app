// JSON alert handlers for /api/v1: tenant-wide alert list + per-user alert
// subscription CRUD. All RequireAuthJSON-gated. The alert list is a tenant
// data view (EffectiveTenantID, impersonation-aware); subscriptions are tied
// to the calling user, so they use the user's own tenant (u.TenantID), matching
// the web settings flow.
package v1

import (
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service"
)

// handleAlertList returns the caller tenant's recent alerts, newest first
// (?limit=, default 100, max 500).
// in: writer, GET /alerts. out: 200 []TenantAlertRow.
func (s *Server) handleAlertList(w http.ResponseWriter, r *http.Request) {
	tenant := authmw.EffectiveTenantID(r)
	rows, err := s.services.Alerts.RecentByTenant(r.Context(), tenant, queryInt(r, "limit", 100, 500))
	if err != nil {
		slog.Error("api alert list failed", "tenant", tenant, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "alert list failed"})
		return
	}
	if rows == nil {
		rows = []service.TenantAlertRow{}
	}
	writeJSON(w, http.StatusOK, rows)
}

// handleSubsList returns the calling user's alert subscriptions.
// in: writer, GET /alert-subscriptions. out: 200 []AlertSubscription.
func (s *Server) handleSubsList(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	subs, err := s.services.Alerts.ListSubscriptions(r.Context(), u.TenantID, u.ID)
	if err != nil {
		slog.Error("api subs list failed", "user_id", u.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "subscription list failed"})
		return
	}
	if subs == nil {
		subs = []service.AlertSubscription{}
	}
	writeJSON(w, http.StatusOK, subs)
}

// subCreateRequest is the POST /alert-subscriptions body. device_pk is optional
// (omitted/null = all the user's devices).
type subCreateRequest struct {
	Channel     string     `json:"channel"`
	MinSeverity string     `json:"min_severity"`
	DevicePK    *uuid.UUID `json:"device_pk"`
}

// handleSubsCreate adds an alert subscription for the calling user. Validates
// channel + min_severity up front (400) so a bad value is not a DB constraint
// 500, and verifies a supplied device_pk belongs to the user's tenant (404).
// in: writer, POST /alert-subscriptions. out: 201 / 400 / 404.
func (s *Server) handleSubsCreate(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	var req subCreateRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Channel != "email" && req.Channel != "telegram" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "channel must be email or telegram"})
		return
	}
	if req.MinSeverity == "" {
		req.MinSeverity = "warn"
	}
	if req.MinSeverity != "info" && req.MinSeverity != "warn" && req.MinSeverity != "crit" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "min_severity must be info, warn, or crit"})
		return
	}
	if req.DevicePK != nil {
		d, err := s.services.Devices.GetByID(*req.DevicePK, u.TenantID)
		if err != nil {
			slog.Error("api subs create: device lookup failed", "device", *req.DevicePK, "err", err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "subscription failed"})
			return
		}
		if d == nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "device not found"})
			return
		}
	}
	if err := s.services.Alerts.CreateSubscription(r.Context(), u.TenantID, u.ID, req.DevicePK, req.Channel, req.MinSeverity); err != nil {
		slog.Error("api subs create failed", "user_id", u.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "subscription failed"})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"status": "created"})
}

// handleSubsDelete removes an alert subscription owned by the calling user.
// Idempotent (the service deletes by id AND user_id, so a foreign or unknown id
// is a no-op).
// in: writer, DELETE /alert-subscriptions/{id}. out: 204 / 400.
func (s *Server) handleSubsDelete(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad subscription id"})
		return
	}
	if err := s.services.Alerts.DeleteSubscription(r.Context(), u.TenantID, id, u.ID); err != nil {
		slog.Error("api subs delete failed", "user_id", u.ID, "sub", id, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "delete failed"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
