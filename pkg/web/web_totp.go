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

func (s *Server) handleLoginSubmitPassword(w http.ResponseWriter, r *http.Request, u *service.User) {
	secret, on, err := s.services.Auth.TOTPSecret(u.TenantID, u.ID)
	if err != nil {
		slog.Error("auth.totp.lookup_failed", "user_id", u.ID, "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	if !on || secret == "" {
		s.startSession(w, r, u, "password")
		http.Redirect(w, r, "/devices", http.StatusFound)
		return
	}
	token, expires, err := s.services.Auth.BeginTOTPLogin(u.TenantID, u.ID)
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
	http.Redirect(w, r, "/login/totp", http.StatusFound)
}

func (s *Server) handleTOTPForm(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(totpPendingCookie); err != nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	s.render(w, r, "login-totp.html", nil)
}

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
	u, err := s.services.Auth.FinishTOTPLogin(c.Value, r.PostFormValue("code"))
	if err != nil {
		if errors.Is(err, service.ErrBadCredentials) {
			s.render(w, r, "login-totp.html", map[string]interface{}{"Error": "That code is not valid."})
			return
		}
		s.clearTOTPCookie(w, r, totpPendingCookie, "/login")
		s.render(w, r, "login.html", map[string]interface{}{"Error": "Sign in again."})
		return
	}
	s.clearTOTPCookie(w, r, totpPendingCookie, "/login")
	s.startSession(w, r, u, "password")
	http.Redirect(w, r, "/devices", http.StatusFound)
}

func (s *Server) handleTOTPBegin(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	if !s.localAccount(w, u) {
		return
	}
	if _, on, err := s.services.Auth.TOTPSecret(u.TenantID, u.ID); err != nil || on {
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
	http.Redirect(w, r, "/settings?saved=totp-setup", http.StatusSeeOther)
}

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
	raw, err := totp.DecodeKey(c.Value)
	if err != nil || !totp.Verify(raw, r.PostFormValue("code"), time.Now()) {
		http.Redirect(w, r, "/settings?err=totp", http.StatusSeeOther)
		return
	}
	if err := s.services.Auth.SetTOTPSecret(u.TenantID, u.ID, c.Value); err != nil {
		slog.Error("auth.totp.save_failed", "user_id", u.ID, "err", err)
		http.Error(w, "could not save authenticator", http.StatusInternalServerError)
		return
	}
	s.clearTOTPCookie(w, r, totpSetupCookie, "/settings")
	http.Redirect(w, r, "/settings?saved=totp", http.StatusSeeOther)
}

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
	if err != nil || !on {
		http.Redirect(w, r, "/settings", http.StatusSeeOther)
		return
	}
	raw, err := totp.DecodeKey(secret)
	if err != nil || !totp.Verify(raw, r.PostFormValue("code"), time.Now()) {
		http.Redirect(w, r, "/settings?err=totp", http.StatusSeeOther)
		return
	}
	if err := s.services.Auth.SetTOTPSecret(u.TenantID, u.ID, ""); err != nil {
		slog.Error("auth.totp.clear_failed", "user_id", u.ID, "err", err)
		http.Error(w, "could not turn off authenticator", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/settings?saved=totp", http.StatusSeeOther)
}

func (s *Server) localAccount(w http.ResponseWriter, u *service.User) bool {
	has, err := s.services.Auth.HasPassword(u.TenantID, u.ID)
	if err != nil || !has {
		http.Error(w, "authenticator is for password accounts", http.StatusForbidden)
		return false
	}
	return true
}

func (s *Server) clearTOTPCookie(w http.ResponseWriter, r *http.Request, name, path string) {
	secure := httpsec.RequestIsSecure(r, s.cfg.TrustedProxies)
	http.SetCookie(w, &http.Cookie{
		Name: name, Value: "", Path: path, MaxAge: -1,
		HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

func totpAuthURL(email, secret string) string {
	return "otpauth://totp/thesada:" + url.PathEscape(email) + "?secret=" + url.QueryEscape(secret) + "&issuer=thesada&period=30&digits=6"
}
