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
	data, ok := s.settingsData(w, r)
	if !ok {
		return
	}
	s.render(w, r, "settings.html", data)
}

// settingsData loads everything the settings page shows. A failed list leaves
// that section empty and sets LoadWarning. Password and TOTP state are a 500.
// in: writer, request (auth required). out: template data, false after a 500.
func (s *Server) settingsData(w http.ResponseWriter, r *http.Request) (map[string]interface{}, bool) {
	data, err := s.loadSettingsData(r)
	if err != nil {
		http.Error(w, "settings load failed", http.StatusInternalServerError)
		return nil, false
	}
	return data, true
}

// loadSettingsData is settingsData without the 500: password or TOTP state
// that fails to load is the error. in: request. out: template data, error.
func (s *Server) loadSettingsData(r *http.Request) (map[string]interface{}, error) {
	u := authmw.CurrentUser(r)
	has, err := s.services.Auth.HasPassword(u.TenantID, u.ID)
	if err != nil {
		slog.Error("settings.load_failed", "part", "password", "user_id", u.ID, "err", err)
		return nil, err
	}
	secret, totpOn, totpErr := s.services.Auth.TOTPSecret(u.TenantID, u.ID)
	if totpErr != nil {
		slog.Error("auth.totp.lookup_failed", "user_id", u.ID, "err", totpErr)
		return nil, totpErr
	}
	warn := false
	subs, err := s.services.Alerts.ListSubscriptions(r.Context(), u.TenantID, u.ID)
	if err != nil {
		slog.Error("settings.load_failed", "part", "subscriptions", "user_id", u.ID, "err", err)
		warn = true
	}
	identities, err := s.services.OAuth.ListIdentitiesForUser(r.Context(), u.TenantID, u.ID)
	if err != nil {
		slog.Error("settings.load_failed", "part", "identities", "user_id", u.ID, "err", err)
		warn = true
	}
	providers, err := s.services.OAuth.ListEnabledProvidersForTenant(r.Context(), u.TenantID)
	if err != nil {
		slog.Error("settings.load_failed", "part", "providers", "user_id", u.ID, "err", err)
		warn = true
	}
	setup, _ := r.Cookie(totpSetupCookie)
	setupSecret := ""
	if setup != nil {
		setupSecret = setup.Value
	}
	return map[string]interface{}{
		"HasPassword":     has,
		"Subscriptions":   subs,
		"SavedSection":    r.URL.Query().Get("saved"),
		"OAuthIdentities": identities,
		"OAuthProviders":  providers,
		"OAuthError":      r.URL.Query().Get("err"),
		"SaveError":       r.URL.Query().Get("err"),
		"TOTPEnabled":     totpOn && secret != "",
		"TOTPSetup":       setupSecret,
		"TOTPURL":         totpAuthURL(u.Email, setupSecret),
		"TOTPError":       r.URL.Query().Get("err") == "totp",
		"LoadWarning":     warn,
	}, nil
}

// handleSettingsProfile updates the user's display name and Telegram chat id.
// in: writer, POST form (display_name, telegram_chat_id). out: redirect to settings, ?err=profile on a failed save.
func (s *Server) handleSettingsProfile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	displayName := strings.TrimSpace(r.PostFormValue("display_name"))
	telegramChatID := strings.TrimSpace(r.PostFormValue("telegram_chat_id"))
	if err := s.services.Auth.UpdateDisplayName(u.TenantID, u.ID, displayName); err != nil {
		slog.Error("settings.save_failed", "part", "display_name", "user_id", u.ID, "err", err)
		http.Redirect(w, r, "/settings?err=profile", http.StatusSeeOther)
		return
	}
	if err := s.services.Auth.UpdateTelegramChatID(u.TenantID, u.ID, telegramChatID); err != nil {
		slog.Error("settings.save_failed", "part", "telegram_chat_id", "user_id", u.ID, "err", err)
		http.Redirect(w, r, "/settings?err=profile", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?saved=profile", http.StatusSeeOther)
}

// handleSettingsNotificationAdd creates a new alert subscription.
// A bad channel, URL, or severity is HTTP 400. A save failure is HTTP 500.
// in: writer, POST form (channel, min_severity, destination). out: redirect or error.
func (s *Server) handleSettingsNotificationAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	channel := r.PostFormValue("channel")
	severity := r.PostFormValue("min_severity")
	destination := strings.TrimSpace(r.PostFormValue("destination"))
	if !service.ValidNotifyChannel(channel) {
		http.Error(w, "invalid channel", http.StatusBadRequest)
		return
	}
	if err := service.WebhookDestinationError(channel, destination, s.cfg.WebhookAllowNets); err != nil {
		http.Error(w, "webhook needs an http(s) URL", http.StatusBadRequest)
		return
	}
	if channel != "webhook" {
		// Email and telegram ignore a pasted URL. Only webhook stores a destination.
		destination = ""
	}
	if severity != "info" && severity != "warn" && severity != "crit" {
		http.Error(w, "invalid severity", http.StatusBadRequest)
		return
	}
	if err := s.services.Alerts.CreateSubscription(r.Context(), u.TenantID, u.ID, nil, channel, severity, destination); err != nil {
		slog.Error("create subscription failed", "user_id", u.ID, "err", err)
		http.Error(w, "could not save notification", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/settings?saved=notifications", http.StatusSeeOther)
}

// handleSettingsNotificationDelete removes an alert subscription.
// in: writer, POST form (sub_id). out: redirect to settings, ?err=notifications on a failed delete.
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
		slog.Error("settings.save_failed", "part", "subscription_delete", "user_id", u.ID, "sub_id", subID, "err", err)
		http.Redirect(w, r, "/settings?err=notifications", http.StatusSeeOther)
		return
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
	formErr := ""
	switch {
	case len(password) < service.MinPasswordLen:
		formErr = passwordFloorMsg
	case password != confirm:
		formErr = "Passwords do not match."
	}
	// The update does not wait on the page's own lookups.
	saved := false
	if formErr == "" {
		if err := s.services.Auth.SetPassword(u.TenantID, u.ID, password); err != nil {
			slog.Error("set password failed", "user_id", u.ID, "err", err)
			formErr = "Could not save password."
		} else {
			saved = true
		}
	}
	data, err := s.loadSettingsData(r)
	if err != nil {
		if saved {
			http.Error(w, "Password updated. The settings page could not load, reload it.", http.StatusOK)
			return
		}
		http.Error(w, "settings load failed", http.StatusInternalServerError)
		return
	}
	if formErr != "" {
		data["Error"] = formErr
	} else {
		data["HasPassword"] = true
		data["Saved"] = true
	}
	s.render(w, r, "settings.html", data)
}
