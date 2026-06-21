package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/httpsec"
	"thesada.app/app/pkg/service"
)

// handleLoginForm renders the email/password + magic link login form.
// in: writer, request. out: HTML form.
func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{}
	if provs, err := s.services.OAuth.ListEnabledProvidersForLogin(r.Context()); err == nil && len(provs) > 0 {
		data["OAuthProviders"] = provs
	}
	s.render(w, r, "login.html", data)
}

// handleLoginSubmit processes login: if a password is provided, verify it and
// start a session; if the password is empty, issue a magic link and email it.
// in: writer, POST form (email, password). out: 302 to /devices on success,
// login.html with error on failure, or login.html with "check your email".
func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	if email == "" {
		s.render(w, r, "login.html", map[string]interface{}{"Error": "Email is required."})
		return
	}

	if password != "" {
		u, err := s.services.Auth.VerifyPasswordAnyTenant(email, password)
		if err != nil {
			if errors.Is(err, service.ErrBadCredentials) {
				s.render(w, r, "login.html", map[string]interface{}{"Error": "Invalid email or password."})
				return
			}
			slog.Error("password verify failed", "email", email, "err", err)
			http.Error(w, "login failed", http.StatusInternalServerError)
			return
		}
		s.startSession(w, r, u, "password")
		http.Redirect(w, r, "/devices", http.StatusFound)
		return
	}

	if !s.allowMagicLink(email, clientIP(r)) {
		s.render(w, r, "login.html", map[string]interface{}{"Sent": true, "Email": email})
		return
	}
	u, err := s.services.Auth.GetUserByEmailAnyTenant(email)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			s.render(w, r, "login.html", map[string]interface{}{"Sent": true, "Email": email})
			return
		}
		slog.Error("user lookup failed", "email", email, "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	token, _, err := s.services.Auth.CreateMagicLink(u.ID)
	if err != nil {
		slog.Error("magic link create failed", "email", email, "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	link := s.cfg.BaseURL + "/login/verify?token=" + token
	textBody, htmlBody, err := s.renderEmail("login_link", map[string]interface{}{"Link": link})
	if err != nil {
		slog.Error("login email render failed", "err", err)
	} else if err := s.mailer.SendMIME(email, "Your thesada sign-in link", textBody, htmlBody); err != nil {
		slog.Error("magic link email failed", "email", email, "err", err)
	}
	s.render(w, r, "login.html", map[string]interface{}{"Sent": true, "Email": email})
}

// handleMagicLinkVerify consumes a magic link token from the URL and starts a session.
// in: writer, request with ?token=. out: 302 to /devices or login.html with error.
func (s *Server) handleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		s.render(w, r, "login.html", map[string]interface{}{"Error": "Missing link token."})
		return
	}
	u, err := s.services.Auth.ConsumeMagicLink(token)
	if err != nil {
		if errors.Is(err, service.ErrExpired) {
			s.render(w, r, "login.html", map[string]interface{}{"Error": "That link has expired. Request a new one."})
			return
		}
		if errors.Is(err, service.ErrNotFound) {
			s.render(w, r, "login.html", map[string]interface{}{"Error": "That link is invalid or already used."})
			return
		}
		slog.Error("magic link consume failed", "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	s.startSession(w, r, u, "magic_link")
	http.Redirect(w, r, "/devices", http.StatusFound)
}

// handleLogout revokes the current session and clears the cookie.
// in: writer, request. out: 302 to /login.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	if c, err := r.Cookie(authmw.CookieName); err == nil && c.Value != "" {
		if err := s.services.Auth.RevokeSession(c.Value); err != nil {
			slog.Warn("session revoke failed", "err", err)
		}
	}
	authmw.ClearSessionCookie(w)
	if u != nil {
		slog.Info("auth.session.state_change",
			"from", "authenticated", "to", "anonymous",
			"user_id", u.ID, "tenant", u.TenantID)
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// startSession creates a new session row and writes the cookie on the response.
// in: writer, request, user, auth method. out: none.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *service.User, method string) {
	ua := r.UserAgent()
	ip := clientIP(r)
	token, expires, err := s.services.Auth.CreateSession(u.TenantID, u.ID, method, ua, ip)
	if err != nil {
		slog.Error("session create failed", "user_id", u.ID, "err", err)
		return
	}
	authmw.SetSessionCookie(w, token, expires, httpsec.RequestIsSecure(r))
	slog.Info("auth.session.state_change",
		"from", "anonymous", "to", "authenticated",
		"user_id", u.ID, "tenant", u.TenantID, "method", method)
}

// clientIP returns the best-guess remote address for the request, stripping the port.
// in: request. out: ip string or "".
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

// handleSignupForm renders the email-only waitlist form.
// in: writer, request. out: HTML form.
func (s *Server) handleSignupForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "signup.html", nil)
}

// handleSignupSubmit inserts the email into the waitlist and re-renders with a thank-you state.
// in: writer, POST form (email, optional note). out: HTML page with confirmation or error.
func (s *Server) handleSignupSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := r.PostFormValue("email")
	note := r.PostFormValue("note")
	if email == "" {
		s.render(w, r, "signup.html", map[string]interface{}{"Error": "Email is required."})
		return
	}
	if _, err := s.services.Auth.AddToWaitlist(bootstrapTenantID, email, note); err != nil {
		slog.Error("waitlist insert failed", "email", email, "err", err)
		s.render(w, r, "signup.html", map[string]interface{}{"Error": "Could not add to waitlist."})
		return
	}
	//  phase 1: plain-text admin notification, deduped 24h per
	// email so a user hammering signup doesn't spam the operator.
	s.notifyAdminWaitlist(email, note, clientIP(r))
	s.render(w, r, "signup.html", map[string]interface{}{"Joined": true, "Email": email})
}

// notifyAdminWaitlist emails THESADA_ADMIN_EMAIL when a new signup lands,
// deduped 24h per lowercase email via waitlistNotify. Email send runs in a
// goroutine so the form response is never blocked on SMTP. No-op if admin
// email is unset (test / dev).
// in: waitlist email, optional note, client IP. out: none.
func (s *Server) notifyAdminWaitlist(email, note, ip string) {
	if s.cfg.AdminEmail == "" {
		return
	}
	key := "signup:" + strings.ToLower(email)
	if !s.waitlistNotify.Allow(key) {
		return
	}
	go func() {
		body := "New waitlist signup on thesada-app\r\n\r\n" +
			"email: " + email + "\r\n"
		if note != "" {
			body += "note:  " + note + "\r\n"
		}
		if ip != "" {
			body += "ip:    " + ip + "\r\n"
		}
		body += "when:  " + time.Now().Format(time.RFC3339) + "\r\n"
		if err := s.mailer.Send(s.cfg.AdminEmail, "thesada: new waitlist signup - "+email, body); err != nil {
			slog.Warn("waitlist admin notify send failed", "admin", s.cfg.AdminEmail, "err", err)
		}
	}()
}

// allowMagicLink consults the per-email and per-IP sliding-window limiters
// and returns false when either bucket is full. Callers treat a false result
// as a silent drop: the user still sees "check your email" so the endpoint
// does not leak which addresses are known or rate-limited.
// in: email, client ip. out: true if both limiters have headroom.
func (s *Server) allowMagicLink(email, ip string) bool {
	if !s.emailLimits.Allow("email:" + strings.ToLower(email)) {
		slog.Warn("magic link email rate-limited", "email", email)
		return false
	}
	if ip != "" && !s.ipLimits.Allow("ip:"+ip) {
		slog.Warn("magic link ip rate-limited", "ip", ip)
		return false
	}
	return true
}

// handleForgotForm renders the "enter your email" password-reset request page.
// in: writer, request. out: HTML form.
func (s *Server) handleForgotForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "forgot.html", nil)
}

// handleForgotSubmit issues a password reset token and emails the link.
// Always renders the same "check your email" confirmation regardless of
// whether the address exists, so the form cannot be used to enumerate users.
// Rate-limited by email and source IP.
// in: writer, POST form (email). out: HTML confirmation page.
func (s *Server) handleForgotSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.PostFormValue("email"))
	if email == "" {
		s.render(w, r, "forgot.html", map[string]interface{}{"Error": "Email is required."})
		return
	}
	confirm := map[string]interface{}{"Sent": true, "Email": email}
	if !s.allowMagicLink(email, clientIP(r)) {
		s.render(w, r, "forgot.html", confirm)
		return
	}
	u, err := s.services.Auth.GetUserByEmailAnyTenant(email)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			s.render(w, r, "forgot.html", confirm)
			return
		}
		slog.Error("forgot user lookup failed", "email", email, "err", err)
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	token, _, err := s.services.Auth.CreateResetLink(u.ID)
	if err != nil {
		slog.Error("reset link create failed", "email", email, "err", err)
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	link := s.cfg.BaseURL + "/reset-password?token=" + token
	textBody, htmlBody, err := s.renderEmail("reset_link", map[string]interface{}{"Link": link})
	if err != nil {
		slog.Error("reset email render failed", "err", err)
	} else if err := s.mailer.SendMIME(email, "Your thesada password reset link", textBody, htmlBody); err != nil {
		slog.Error("reset email failed", "email", email, "err", err)
	}
	s.render(w, r, "forgot.html", confirm)
}

// handleResetForm renders the "set a new password" form after validating the
// reset token. The token is not consumed here so the user can still submit
// the form; consumption happens in handleResetSubmit on success.
// in: writer, request with ?token=. out: HTML form or error page.
func (s *Server) handleResetForm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		s.render(w, r, "reset.html", map[string]interface{}{"Error": "Missing reset token."})
		return
	}
	if _, _, err := s.services.Auth.ConsumeResetLink(token); err != nil {
		s.render(w, r, "reset.html", map[string]interface{}{"Error": resetErrMessage(err)})
		return
	}
	s.render(w, r, "reset.html", map[string]interface{}{"Token": token})
}

// handleResetSubmit revalidates the token, stores the new bcrypt password
// hash, and marks the token consumed. On success the user is redirected to
// /login so they can sign in with the new password.
// in: writer, POST form (token, password, confirm). out: redirect or error.
func (s *Server) handleResetSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	token := r.PostFormValue("token")
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")
	if token == "" {
		s.render(w, r, "reset.html", map[string]interface{}{"Error": "Missing reset token."})
		return
	}
	u, tokenID, err := s.services.Auth.ConsumeResetLink(token)
	if err != nil {
		s.render(w, r, "reset.html", map[string]interface{}{"Error": resetErrMessage(err)})
		return
	}
	if len(password) < 10 {
		s.render(w, r, "reset.html", map[string]interface{}{"Token": token, "Error": "Password must be at least 10 characters."})
		return
	}
	if password != confirm {
		s.render(w, r, "reset.html", map[string]interface{}{"Token": token, "Error": "Passwords do not match."})
		return
	}
	if err := s.services.Auth.SetPassword(u.TenantID, u.ID, password); err != nil {
		slog.Error("reset set password failed", "user_id", u.ID, "err", err)
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	if err := s.services.Auth.MarkResetConsumed(tokenID); err != nil {
		slog.Warn("reset token mark consumed failed", "err", err)
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// resetErrMessage maps an auth service error to a user-visible reset-page string.
// in: error from ConsumeResetLink. out: message safe to show to the caller.
func resetErrMessage(err error) string {
	if errors.Is(err, service.ErrExpired) {
		return "That reset link has expired. Request a new one."
	}
	return "That reset link is invalid or already used."
}
