package web

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

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
		"ConfirmState":    r.URL.Query().Get("confirm"),
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

// channelTooLongMsg names the channel field caps.
var channelTooLongMsg = fmt.Sprintf("label (%d) or target (%d characters) too long", service.MaxChannelLabelLen, service.MaxChannelTargetLen)

// formChecked reads a checkbox or a hidden true/false field. in: request, field. out: on.
func formChecked(r *http.Request, field string) bool {
	v := r.PostFormValue(field)
	return v == "on" || v == "true"
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
	id, err := s.services.Alerts.CreateChannel(r.Context(), u.TenantID, u.ID, kind, r.PostFormValue("target"), r.PostFormValue("label"))
	if errors.Is(err, service.ErrBadChannelTarget) || errors.Is(err, service.ErrBadWebhook) {
		http.Error(w, channelTargetHint(kind), http.StatusBadRequest)
		return
	}
	if errors.Is(err, service.ErrChannelTooLong) {
		http.Error(w, channelTooLongMsg, http.StatusBadRequest)
		return
	}
	if err != nil {
		slog.Error("settings.save_failed", "part", "channel_add", "user_id", u.ID, "err", err)
		http.Redirect(w, r, "/settings?err=channels#notifications", http.StatusSeeOther)
		return
	}
	state, _ := s.sendChannelConfirm(r, u, id, false)
	http.Redirect(w, r, "/settings?saved=channels"+state+"#notifications", http.StatusSeeOther)
}

// channelConfirmWindow and channelConfirmMax cap confirm mails per user.
const (
	channelConfirmWindow = time.Hour
	channelConfirmMax    = 3
)

// sendChannelConfirm mails a confirm link when the channel needs one.
// in: request, user, channel id, resend. out: query suffix for the redirect, ErrNotFound when not the user's.
func (s *Server) sendChannelConfirm(r *http.Request, u *service.User, id uuid.UUID, resend bool) (string, error) {
	target, token, err := s.services.Alerts.IssueChannelConfirm(r.Context(), u.TenantID, u.ID, id, resend,
		func() bool { return s.channelConfirms.Allow(u.ID.String()) })
	switch {
	case errors.Is(err, service.ErrConfirmLimited):
		slog.Warn("settings.channel_confirm.rate_limited", "user_id", u.ID, "channel_id", id)
		return "&confirm=later", nil
	case errors.Is(err, service.ErrNotFound):
		return "", err
	case err != nil:
		slog.Error("settings.channel_confirm.issue_failed", "user_id", u.ID, "channel_id", id, "err", err)
		return "&confirm=failed", err
	case token == "":
		return "", nil
	}
	if s.notes != nil {
		if err := s.notes.SendChannelConfirm(target, token); err != nil {
			slog.Error("settings.channel_confirm.send_failed", "user_id", u.ID, "channel_id", id, "err", err)
			return "&confirm=failed", err
		}
	}
	return "&confirm=sent", nil
}

// handleSettingsChannelResend mails a new confirm link for an unconfirmed email channel.
// in: writer, path id. out: redirect, 404 when not the user's channel.
func (s *Server) handleSettingsChannelResend(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid channel", http.StatusBadRequest)
		return
	}
	state, err := s.sendChannelConfirm(r, u, id, true)
	if errors.Is(err, service.ErrNotFound) {
		http.Error(w, "channel not found", http.StatusNotFound)
		return
	}
	http.Redirect(w, r, "/settings?saved=channels"+state+"#notifications", http.StatusSeeOther)
}

// handleChannelConfirmForm shows the confirm button. It changes nothing, so a
// mail scanner following the link confirms nothing.
// in: writer, query token. out: HTML page.
func (s *Server) handleChannelConfirmForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	token := r.URL.Query().Get("token")
	ok := false
	if token != "" {
		var err error
		if ok, err = s.services.Alerts.ChannelConfirmValid(r.Context(), token); err != nil {
			slog.Error("channel_confirm.check_failed", "err", err)
			http.Error(w, "confirm failed", http.StatusInternalServerError)
			return
		}
	}
	s.render(w, r, "channel-confirm.html", map[string]interface{}{"Token": token, "Invalid": !ok})
}

// handleChannelConfirm uses the confirm link. Unknown, used and expired links
// all get the same page.
// in: writer, POST form (token). out: HTML page.
func (s *Server) handleChannelConfirm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	token := r.PostFormValue("token")
	err := service.ErrNotFound
	if token != "" {
		err = s.services.Alerts.ConfirmChannel(r.Context(), token)
	}
	if err != nil && !errors.Is(err, service.ErrNotFound) {
		slog.Error("channel_confirm.failed", "err", err)
		http.Error(w, "confirm failed", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "channel-confirm.html", map[string]interface{}{"Confirmed": err == nil, "Invalid": err != nil})
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
		r.PostFormValue("target"), r.PostFormValue("label"), formChecked(r, "enabled"))
	switch {
	case errors.Is(err, service.ErrNotFound):
		http.Error(w, "channel not found", http.StatusNotFound)
	case errors.Is(err, service.ErrBadChannelTarget), errors.Is(err, service.ErrBadWebhook):
		http.Error(w, "target does not fit the channel type", http.StatusBadRequest)
	case errors.Is(err, service.ErrChannelTooLong):
		http.Error(w, channelTooLongMsg, http.StatusBadRequest)
	case errors.Is(err, service.ErrChannelExists):
		slog.Info("settings channel update refused, duplicate target", "user_id", u.ID, "channel", id, "err", err)
		http.Error(w, "you already have a channel with that target", http.StatusBadRequest)
	case err != nil:
		slog.Error("settings.save_failed", "part", "channel_update", "user_id", u.ID, "err", err)
		http.Redirect(w, r, "/settings?err=channels#notifications", http.StatusSeeOther)
	default:
		state, _ := s.sendChannelConfirm(r, u, id, false)
		http.Redirect(w, r, "/settings?saved=channels"+state+"#notifications", http.StatusSeeOther)
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
	err = s.services.Alerts.SetChannelEnabled(r.Context(), u.TenantID, u.ID, id, formChecked(r, "enabled"))
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
