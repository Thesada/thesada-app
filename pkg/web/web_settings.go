package web

import (
	"errors"
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
	channels, err := s.services.Alerts.ListChannels(r.Context(), u.TenantID, u.ID)
	if err != nil {
		slog.Error("settings.load_failed", "part", "channels", "user_id", u.ID, "err", err)
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
	var passkeys []service.Passkey
	if has {
		if passkeys, err = s.services.Auth.ListPasskeys(u.TenantID, u.ID); err != nil {
			slog.Error("settings.load_failed", "part", "passkeys", "user_id", u.ID, "err", err)
			warn = true
		}
	}
	setup, _ := r.Cookie(totpSetupCookie)
	setupSecret := ""
	if setup != nil {
		setupSecret = setup.Value
	}
	return map[string]interface{}{
		"HasPassword":     has,
		"HomeTenantID":    u.TenantID,
		"Subscriptions":   subs,
		"Channels":        channels,
		"SavedSection":    r.URL.Query().Get("saved"),
		"OAuthIdentities": identities,
		"OAuthProviders":  providers,
		"OAuthError":      r.URL.Query().Get("err"),
		"SaveError":       r.URL.Query().Get("err"),
		"TOTPEnabled":     totpOn && secret != "",
		"TOTPSetup":       setupSecret,
		"TOTPURL":         totpAuthURL(u.Email, setupSecret),
		"TOTPError":       r.URL.Query().Get("err") == "totp",
		"Passkeys":        passkeys,
		"PasskeysEnabled": s.services.Auth.PasskeysEnabled(),
		"PasskeyError":    r.URL.Query().Get("err") == "passkey-password",
		"LoadWarning":     warn,
	}, nil
}

// handleSettingsProfile updates the user's display name.
// in: writer, POST form (display_name). out: redirect to settings, ?err=profile on a failed save.
func (s *Server) handleSettingsProfile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	displayName := strings.TrimSpace(r.PostFormValue("display_name"))
	if err := s.services.Auth.UpdateDisplayName(u.TenantID, u.ID, displayName); err != nil {
		slog.Error("settings.save_failed", "part", "display_name", "user_id", u.ID, "err", err)
		http.Redirect(w, r, "/settings?err=profile", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?saved=profile", http.StatusSeeOther)
}

// handleSettingsChannelAdd adds a notification channel. A target that does not
// fit the kind is HTTP 400.
// in: writer, POST form (kind, target, label). out: redirect or error.
func (s *Server) handleSettingsChannelAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	kind := r.PostFormValue("kind")
	if !service.ValidNotifyChannel(kind) {
		http.Error(w, "invalid channel type", http.StatusBadRequest)
		return
	}
	_, err := s.services.Alerts.CreateChannel(r.Context(), u.TenantID, u.ID, kind, r.PostFormValue("target"), r.PostFormValue("label"))
	if errors.Is(err, service.ErrBadChannelTarget) || errors.Is(err, service.ErrBadWebhook) {
		http.Error(w, channelTargetHint(kind), http.StatusBadRequest)
		return
	}
	if err != nil {
		slog.Error("settings.save_failed", "part", "channel_add", "user_id", u.ID, "err", err)
		http.Redirect(w, r, "/settings?err=channels#notifications", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?saved=channels#notifications", http.StatusSeeOther)
}

// channelTargetHint is the 400 text for a target that does not fit its kind.
func channelTargetHint(kind string) string {
	switch kind {
	case "email":
		return "email needs a plain address like name@example.com"
	case "telegram":
		return "telegram needs a numeric chat id"
	default:
		return "webhook needs an http(s) URL"
	}
}

// handleSettingsChannelUpdate edits target, label and enabled of one channel.
// in: writer, POST form (target, label, enabled), path id. out: redirect or error.
func (s *Server) handleSettingsChannelUpdate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid channel", http.StatusBadRequest)
		return
	}
	err = s.services.Alerts.UpdateChannel(r.Context(), u.TenantID, u.ID, id,
		r.PostFormValue("target"), r.PostFormValue("label"), r.PostFormValue("enabled") == "on")
	switch {
	case errors.Is(err, service.ErrNotFound):
		http.Error(w, "channel not found", http.StatusNotFound)
	case errors.Is(err, service.ErrBadChannelTarget), errors.Is(err, service.ErrBadWebhook):
		http.Error(w, "target does not fit the channel type", http.StatusBadRequest)
	case err != nil:
		slog.Error("settings.save_failed", "part", "channel_update", "user_id", u.ID, "err", err)
		http.Redirect(w, r, "/settings?err=channels#notifications", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/settings?saved=channels#notifications", http.StatusSeeOther)
	}
}

// handleSettingsChannelToggle switches one channel on or off.
// in: writer, POST form (enabled), path id. out: redirect or error.
func (s *Server) handleSettingsChannelToggle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid channel", http.StatusBadRequest)
		return
	}
	err = s.services.Alerts.SetChannelEnabled(r.Context(), u.TenantID, u.ID, id, r.PostFormValue("enabled") == "true")
	switch {
	case errors.Is(err, service.ErrNotFound):
		http.Error(w, "channel not found", http.StatusNotFound)
	case err != nil:
		slog.Error("settings.save_failed", "part", "channel_toggle", "user_id", u.ID, "err", err)
		http.Redirect(w, r, "/settings?err=channels#notifications", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/settings?saved=channels#notifications", http.StatusSeeOther)
	}
}

// handleSettingsChannelDelete removes one channel and the rules that use it.
// in: writer, path id. out: redirect or error.
func (s *Server) handleSettingsChannelDelete(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid channel", http.StatusBadRequest)
		return
	}
	err = s.services.Alerts.DeleteChannel(r.Context(), u.TenantID, u.ID, id)
	switch {
	case errors.Is(err, service.ErrNotFound):
		http.Error(w, "channel not found", http.StatusNotFound)
	case err != nil:
		slog.Error("settings.save_failed", "part", "channel_delete", "user_id", u.ID, "err", err)
		http.Redirect(w, r, "/settings?err=channels#notifications", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/settings?saved=channels#notifications", http.StatusSeeOther)
	}
}

// handleSettingsNotificationAdd subscribes one of the user's channels to alerts.
// A bad channel or severity is HTTP 400. A save failure is HTTP 500.
// in: writer, POST form (channel_id, min_severity). out: redirect or error.
func (s *Server) handleSettingsNotificationAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	channelID, err := uuid.Parse(r.PostFormValue("channel_id"))
	if err != nil {
		http.Error(w, "invalid channel", http.StatusBadRequest)
		return
	}
	severity := r.PostFormValue("min_severity")
	if severity != "info" && severity != "warn" && severity != "crit" {
		http.Error(w, "invalid severity", http.StatusBadRequest)
		return
	}
	err = s.services.Alerts.CreateChannelSubscription(r.Context(), u.TenantID, u.ID, nil, channelID, severity)
	if errors.Is(err, service.ErrNotFound) {
		http.Error(w, "channel not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("create subscription failed", "user_id", u.ID, "err", err)
		http.Error(w, "could not save notification", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/settings?saved=notifications#notifications", http.StatusSeeOther)
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
		http.Redirect(w, r, "/settings?err=notifications#notifications", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?saved=notifications#notifications", http.StatusSeeOther)
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
