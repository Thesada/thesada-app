package web

import (
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/httpsec"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/totp"
)

const (
	totpPendingCookie = "totp_pending"
	totpSetupCookie   = "totp_setup"
)

// continueLocalLogin opens a session, or a TOTP challenge when the account enrolled one.
// in: writer, request, user, session method. out: redirect or 500.
func (s *Server) continueLocalLogin(w http.ResponseWriter, r *http.Request, u *service.User, method string) {
	_, required, err := s.services.Auth.EnrolledTOTP(u.TenantID, u.ID)
	if err != nil {
		slog.Error("auth.totp.lookup_failed", "user_id", u.ID, "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	if !required {
		s.startSession(w, r, u, method)
		http.Redirect(w, r, "/devices", http.StatusFound)
		return
	}
	token, expires, err := s.services.Auth.BeginTOTPLogin(u.TenantID, u.ID, method)
	if err != nil {
		slog.Error("auth.totp.challenge_failed", "user_id", u.ID, "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	secure := httpsec.RequestIsSecure(r, s.cfg.TrustedProxies)
	http.SetCookie(w, &http.Cookie{
		Name: totpPendingCookie, Value: token, Path: "/login",
		Expires: expires, HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
	slog.Info("auth.totp.state_change",
		"from", method, "to", "challenged",
		"user_id", u.ID, "tenant", u.TenantID)
	http.Redirect(w, r, "/login/totp", http.StatusFound)
}

// handleTOTPForm renders the code form when a challenge cookie is present.
// in: writer, GET /login/totp. out: HTML or redirect to /login.
func (s *Server) handleTOTPForm(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(totpPendingCookie); err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.render(w, r, "login-totp.html", nil)
}

// handleTOTPSubmit checks the challenge cookie and opens the session.
// A bad code redisplays the form. A decode or lookup failure is HTTP 500.
// in: writer, POST /login/totp. out: redirect, the code form, or 500.
func (s *Server) handleTOTPSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ip := s.clientIP(r)
	if !s.services.Auth.AllowTOTPAttempt(ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		s.render(w, r, "login-totp.html", map[string]interface{}{"Error": "Too many attempts. Wait a few minutes and try again."})
		return
	}
	c, err := r.Cookie(totpPendingCookie)
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	u, method, err := s.services.Auth.FinishTOTPLoginAny(c.Value, r.PostFormValue("code"))
	if err != nil {
		if errors.Is(err, service.ErrBadCredentials) {
			s.render(w, r, "login-totp.html", map[string]interface{}{"Error": "That code is not valid."})
			return
		}
		if errors.Is(err, service.ErrExpired) {
			s.clearTOTPCookie(w, r, totpPendingCookie, "/login")
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		slog.Error("auth.totp.finish_failed", "err", err)
		s.clearTOTPCookie(w, r, totpPendingCookie, "/login")
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	s.clearTOTPCookie(w, r, totpPendingCookie, "/login")
	slog.Info("auth.totp.state_change",
		"from", "challenged", "to", "passed",
		"user_id", u.ID, "tenant", u.TenantID, "method", method)
	s.startSession(w, r, u, method)
	http.Redirect(w, r, "/devices", http.StatusFound)
}

// handleTOTPBegin starts authenticator enrollment for a password account.
// in: writer, POST /settings/totp/begin. out: redirect.
func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	if !s.localAccount(w, u) {
		return
	}
	secret, on, err := s.services.Auth.TOTPSecret(u.TenantID, u.ID)
	if err != nil {
		slog.Error("auth.totp.lookup_failed", "user_id", u.ID, "err", err)
		http.Error(w, "settings failed", http.StatusInternalServerError)
		return
	}
	if on && secret != "" {
		http.Redirect(w, r, "/settings?saved=totp", http.StatusSeeOther)
		return
	}
	_, encoded, err := totp.NewKey()
	if err != nil {
		http.Error(w, "could not start authenticator setup", http.StatusInternalServerError)
		return
	}
	secure := httpsec.RequestIsSecure(r, s.cfg.TrustedProxies)
	http.SetCookie(w, &http.Cookie{
		Name: totpSetupCookie, Value: encoded, Path: "/settings",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
	slog.Info("auth.totp.state_change",
		"from", "off", "to", "pending",
		"user_id", u.ID, "tenant", u.TenantID)
	http.Redirect(w, r, "/settings?saved=totp-setup", http.StatusSeeOther)
}

// handleTOTPConfirm stores the secret after the setup code matches.
// in: writer, POST /settings/totp/confirm. out: redirect or 500.
func (s *Server) handleTOTPConfirm(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	if !s.localAccount(w, u) {
		return
	}
	c, err := r.Cookie(totpSetupCookie)
	if err != nil || c.Value == "" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	rawOK, err := totp.Check(c.Value, r.PostFormValue("code"), time.Now())
	if err != nil {
		slog.Error("auth.totp.setup_code_failed", "user_id", u.ID, "err", err)
		http.Error(w, "could not check authenticator code", http.StatusInternalServerError)
		return
	}
	if !rawOK {
		http.Redirect(w, r, "/settings?err=totp", http.StatusSeeOther)
		return
	}
	if err := s.services.Auth.SetTOTPSecret(u.TenantID, u.ID, c.Value); err != nil {
		slog.Error("auth.totp.save_failed", "user_id", u.ID, "err", err)
		http.Error(w, "could not save authenticator", http.StatusInternalServerError)
		return
	}
	s.clearTOTPCookie(w, r, totpSetupCookie, "/settings")
	slog.Info("auth.totp.state_change",
		"from", "pending", "to", "on",
		"user_id", u.ID, "tenant", u.TenantID)
	http.Redirect(w, r, "/settings?saved=totp", http.StatusSeeOther)
}

// handleTOTPDisable clears the secret after a valid code.
// in: writer, POST /settings/totp/disable. out: redirect or 500.
func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	if !s.localAccount(w, u) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	secret, on, err := s.services.Auth.TOTPSecret(u.TenantID, u.ID)
	if err != nil {
		slog.Error("auth.totp.lookup_failed", "user_id", u.ID, "err", err)
		http.Error(w, "settings failed", http.StatusInternalServerError)
		return
	}
	if !on || secret == "" {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	ok, err := totp.Check(secret, r.PostFormValue("code"), time.Now())
	if err != nil {
		slog.Error("auth.totp.disable_code_failed", "user_id", u.ID, "err", err)
		http.Error(w, "could not check authenticator code", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Redirect(w, r, "/settings?err=totp", http.StatusSeeOther)
		return
	}
	if err := s.services.Auth.SetTOTPSecret(u.TenantID, u.ID, ""); err != nil {
		slog.Error("auth.totp.clear_failed", "user_id", u.ID, "err", err)
		http.Error(w, "could not turn off authenticator", http.StatusInternalServerError)
		return
	}
	slog.Info("auth.totp.state_change",
		"from", "on", "to", "off",
		"user_id", u.ID, "tenant", u.TenantID)
	http.Redirect(w, r, "/settings?saved=totp", http.StatusSeeOther)
}

// localAccount reports whether this user has a password. Kanidm accounts get 403.
// in: writer, user. out: true when authenticator setup may continue.
func (s *Server) localAccount(w http.ResponseWriter, u *service.User) bool {
	has, err := s.services.Auth.HasPassword(u.TenantID, u.ID)
	if err != nil {
		slog.Error("auth.password.lookup_failed", "user_id", u.ID, "err", err)
		http.Error(w, "settings failed", http.StatusInternalServerError)
		return false
	}
	if !has {
		http.Error(w, "authenticator is for password accounts", http.StatusForbidden)
		return false
	}
	return true
}

// clearTOTPCookie expires one TOTP cookie on path.
// in: writer, request, cookie name, path. out: Set-Cookie.
func (s *Server) clearTOTPCookie(w http.ResponseWriter, r *http.Request, name, path string) {
	secure := httpsec.RequestIsSecure(r, s.cfg.TrustedProxies)
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: path, MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

// totpAuthURL is the otpauth link shown while enrollment is pending.
// in: email, base32 secret. out: otpauth URL.
func totpAuthURL(email, secret string) string {
	return "otpauth://totp/thesada:" + url.PathEscape(email) + "?secret=" + url.QueryEscape(secret) + "&issuer=thesada&period=30&digits=6"
}
