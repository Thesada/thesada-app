package web

import (
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service"
)

// handleSettingsForm renders the account settings page with a set/change password form.
// in: writer, request (auth required). out: HTML form with HasPassword flag.
func (s *Server) handleSettingsForm(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	has, err := s.services.Auth.HasPassword(u.TenantID, u.ID)
	if err != nil {
		slog.Error("has-password query failed", "user_id", u.ID, "err", err)
		http.Error(w, "settings load failed", http.StatusInternalServerError)
		return
	}
	subs, _ := s.services.Alerts.ListSubscriptions(r.Context(), u.TenantID, u.ID)
	savedSection := r.URL.Query().Get("saved")
	identities, _ := s.services.OAuth.ListIdentitiesForUser(r.Context(), u.TenantID, u.ID)
	providers, _ := s.services.OAuth.ListEnabledProvidersForTenant(r.Context(), u.TenantID)
	s.render(w, r, "settings.html", map[string]interface{}{
		"HasPassword":     has,
		"Subscriptions":   subs,
		"SavedSection":    savedSection,
		"OAuthIdentities": identities,
		"OAuthProviders":  providers,
		"OAuthError":      r.URL.Query().Get("err"),
	})
}

// handleSettingsProfile updates the user's display name.
// in: writer, POST form (display_name). out: redirect to settings.
func (s *Server) handleSettingsProfile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	displayName := strings.TrimSpace(r.PostFormValue("display_name"))
	telegramChatID := strings.TrimSpace(r.PostFormValue("telegram_chat_id"))
	if err := s.services.Auth.UpdateDisplayName(u.TenantID, u.ID, displayName); err != nil {
		slog.Error("update display name failed", "user_id", u.ID, "err", err)
	}
	if err := s.services.Auth.UpdateTelegramChatID(u.TenantID, u.ID, telegramChatID); err != nil {
		slog.Error("update telegram chat_id failed", "user_id", u.ID, "err", err)
	}
	http.Redirect(w, r, "/settings?saved=profile", http.StatusSeeOther)
}

// handleSettingsNotificationAdd creates a new alert subscription.
// in: writer, POST form (channel, min_severity). out: redirect to settings.
func (s *Server) handleSettingsNotificationAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	channel := r.PostFormValue("channel")
	severity := r.PostFormValue("min_severity")
	if channel != "email" && channel != "telegram" {
		http.Error(w, "invalid channel", http.StatusBadRequest)
		return
	}
	if severity != "info" && severity != "warn" && severity != "crit" {
		severity = "warn"
	}
	if err := s.services.Alerts.CreateSubscription(r.Context(), u.TenantID, u.ID, nil, channel, severity); err != nil {
		slog.Error("create subscription failed", "user_id", u.ID, "err", err)
	}
	http.Redirect(w, r, "/settings?saved=notifications", http.StatusSeeOther)
}

// handleSettingsNotificationDelete removes an alert subscription.
// in: writer, POST form (sub_id). out: redirect to settings.
func (s *Server) handleSettingsNotificationDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	subID, err := uuid.Parse(r.PostFormValue("sub_id"))
	if err != nil {
		http.Error(w, "invalid sub_id", http.StatusBadRequest)
		return
	}
	if err := s.services.Alerts.DeleteSubscription(r.Context(), u.TenantID, subID, u.ID); err != nil {
		slog.Error("delete subscription failed", "user_id", u.ID, "sub_id", subID, "err", err)
	}
	http.Redirect(w, r, "/settings?saved=notifications", http.StatusSeeOther)
}

// handleSettingsPassword validates the POSTed new password and stores a bcrypt hash.
// Enforces min length 10 and a matching confirm field. Re-renders with error or success flash.
// in: writer, POST form (password, confirm). out: HTML page.
func (s *Server) handleSettingsPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")
	has, _ := s.services.Auth.HasPassword(u.TenantID, u.ID)
	data := map[string]interface{}{"HasPassword": has}
	if len(password) < service.MinPasswordLen {
		data["Error"] = "Password must be at least 10 characters."
		s.render(w, r, "settings.html", data)
		return
	}
	if password != confirm {
		data["Error"] = "Passwords do not match."
		s.render(w, r, "settings.html", data)
		return
	}
	if err := s.services.Auth.SetPassword(u.TenantID, u.ID, password); err != nil {
		slog.Error("set password failed", "user_id", u.ID, "err", err)
		data["Error"] = "Could not save password."
		s.render(w, r, "settings.html", data)
		return
	}
	data["HasPassword"] = true
	data["Saved"] = true
	s.render(w, r, "settings.html", data)
}
