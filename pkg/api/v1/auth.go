// JSON auth handlers for /api/v1/auth/*: password login, logout, waitlist signup.
// Magic-link is a stub until email templates + rate-limiters move out of pkg/web.
package v1

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/httpsec"
	"thesada.app/app/pkg/service"
)

// apiBootstrapTenantID is the tenant pre-auth flows (signup waitlist) write to.
// Mirrors pkg/web.bootstrapTenantID (unexported there); both are "default".
const apiBootstrapTenantID = "default"

// loginRequest is the POST /auth/login body.
type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// userResponse is the redacted user shape returned by the auth endpoints -
// never the password hash or internal-only fields.
type userResponse struct {
	ID           uuid.UUID `json:"id"`
	Email        string    `json:"email"`
	DisplayName  *string   `json:"display_name"`
	TenantID     string    `json:"tenant_id"`
	IsAdmin      bool      `json:"is_admin"`
	IsSuperAdmin bool      `json:"is_super_admin"`
}

// loginResponse is the POST /auth/login success body; Token is the bearer credential, cookie serves web-origin consumers.
type loginResponse struct {
	Token     string       `json:"token"`
	ExpiresAt time.Time    `json:"expires_at"`
	User      userResponse `json:"user"`
}

// toUserResponse maps a service.User to its redacted API shape.
// in: *service.User. out: userResponse.
func toUserResponse(u *service.User) userResponse {
	return userResponse{
		ID:           u.ID,
		Email:        u.Email,
		DisplayName:  u.DisplayName,
		TenantID:     u.TenantID,
		IsAdmin:      u.IsAdmin,
		IsSuperAdmin: u.IsSuperAdmin,
	}
}

// handleAuthLogin verifies email + password, sets a session cookie, and issues a bearer token.
// in: writer, POST /auth/login {email,password}. out: 200 loginResponse / 400 / 401.
func (s *Server) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	email := strings.TrimSpace(req.Email)
	if email == "" || req.Password == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and password are required"})
		return
	}

	ip := s.clientIP(r)
	u, err := s.services.Auth.VerifyPasswordAnyTenant(email, req.Password, ip)
	if err != nil {
		if errors.Is(err, service.ErrBadCredentials) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid email or password"})
			return
		}
		if errors.Is(err, service.ErrLoginRateLimited) {
			slog.Warn("auth.login.rate_limited", "ip", ip, "surface", "api")
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many attempts, try again later"})
			return
		}
		slog.Error("api login: verify failed", "email", email, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "login failed"})
		return
	}

	cookieTok, cookieExp, err := s.services.Auth.CreateSession(u.TenantID, u.ID, "password", r.UserAgent(), ip)
	if err != nil {
		slog.Error("api login: session create failed", "user_id", u.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "login failed"})
		return
	}
	authmw.SetSessionCookie(w, cookieTok, cookieExp, httpsec.RequestIsSecure(r, s.cfg.TrustedProxies))

	token, expires, err := s.services.ApiTokens.IssueToken(u.TenantID, u.ID, "api login")
	if err != nil {
		slog.Error("api login: token issue failed", "user_id", u.ID, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "login failed"})
		return
	}

	slog.Info("auth.session.state_change",
		"from", "anonymous", "to", "authenticated",
		"user_id", u.ID, "tenant", u.TenantID, "method", "password", "surface", "api")

	writeJSON(w, http.StatusOK, loginResponse{Token: token, ExpiresAt: expires, User: toUserResponse(u)})
}

// handleAuthLogout revokes the bearer token and/or session cookie; idempotent, safe unauthenticated.
// in: writer, POST /auth/logout. out: 200 {"status":"ok"}.
func (s *Server) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	if tok := authmw.BearerToken(r); tok != "" {
		if err := s.services.ApiTokens.RevokeToken(tok); err != nil {
			slog.Warn("api logout: token revoke failed", "err", err)
		}
	}
	if c, err := r.Cookie(authmw.CookieName); err == nil && c.Value != "" {
		if err := s.services.Auth.RevokeSession(c.Value); err != nil {
			slog.Warn("api logout: session revoke failed", "err", err)
		}
		authmw.ClearSessionCookie(w, httpsec.RequestIsSecure(r, s.cfg.TrustedProxies))
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// signupRequest is the POST /auth/signup body.
type signupRequest struct {
	Email string `json:"email"`
	Note  string `json:"note"`
}

// handleAuthSignup adds email to the waitlist; always 200 to avoid user enumeration.
// in: writer, POST /auth/signup {email,note?}. out: 200 {"status":"ok"} / 400.
func (s *Server) handleAuthSignup(w http.ResponseWriter, r *http.Request) {
	var req signupRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	email := strings.TrimSpace(req.Email)
	if email == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email is required"})
		return
	}
	if _, err := s.services.Auth.AddToWaitlist(apiBootstrapTenantID, email, req.Note); err != nil {
		slog.Error("api signup: waitlist insert failed", "email", email, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "could not add to waitlist"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
