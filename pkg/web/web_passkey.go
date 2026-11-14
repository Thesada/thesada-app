package web

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service"
)

const passkeyRegCookie = "passkey_reg"

// maxPasskeyBody caps a ceremony JSON body. An attestation without certificates is a few KB.
const maxPasskeyBody = 32 << 10

// passkeyRegisterRequest is the settings begin body: the fresh password check.
type passkeyRegisterRequest struct {
	Password string `json:"password"`
}

// passkeyFinishRequest carries the authenticator's answer and, on enroll, a key name.
type passkeyFinishRequest struct {
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

// handlePasskeyLoginBegin answers the assertion options for a pending challenge.
// in: writer, POST /login/passkey/begin. out: JSON options or JSON error.
func (s *Server) handlePasskeyLoginBegin(w http.ResponseWriter, r *http.Request) {
	if !s.services.Auth.AllowTOTPAttempt(s.clientIP(r)) {
		writePasskeyError(w, http.StatusTooManyRequests, "Too many attempts. Wait a few minutes and try again.")
		return
	}
	c, err := r.Cookie(totpPendingCookie)
	if err != nil || c.Value == "" {
		writePasskeyJSON(w, http.StatusUnauthorized, map[string]string{"redirect": "/login"})
		return
	}
	opts, err := s.services.Auth.BeginPasskeyLoginAny(c.Value)
	if err != nil {
		s.passkeyLoginFailed(w, err, "begin")
		return
	}
	writeRawJSON(w, opts)
}

// handlePasskeyLoginFinish checks the assertion and opens the session.
// in: writer, POST /login/passkey/finish. out: JSON redirect or JSON error.
func (s *Server) handlePasskeyLoginFinish(w http.ResponseWriter, r *http.Request) {
	if !s.services.Auth.AllowTOTPAttempt(s.clientIP(r)) {
		writePasskeyError(w, http.StatusTooManyRequests, "Too many attempts. Wait a few minutes and try again.")
		return
	}
	c, err := r.Cookie(totpPendingCookie)
	if err != nil || c.Value == "" {
		writePasskeyJSON(w, http.StatusUnauthorized, map[string]string{"redirect": "/login"})
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxPasskeyBody))
	if err != nil {
		writePasskeyError(w, http.StatusBadRequest, "That passkey was not accepted.")
		return
	}
	u, method, err := s.services.Auth.FinishPasskeyLoginAny(c.Value, body)
	if err != nil {
		if errors.Is(err, service.ErrExpired) {
			s.clearTOTPCookie(w, totpPendingCookie, "/login")
		}
		s.passkeyLoginFailed(w, err, "finish")
		return
	}
	s.clearTOTPCookie(w, totpPendingCookie, "/login")
	slog.Info("auth.passkey.state_change",
		"from", "challenged", "to", "passed",
		"user_id", u.ID, "tenant", u.TenantID, "method", method)
	if err := s.startSession(w, r, u, method); err != nil {
		writePasskeyError(w, http.StatusInternalServerError, "Login failed.")
		return
	}
	writePasskeyJSON(w, http.StatusOK, map[string]string{"redirect": "/devices"})
}

// passkeyLoginFailed maps a login ceremony error to its JSON answer.
// in: writer, error, step. out: JSON response.
func (s *Server) passkeyLoginFailed(w http.ResponseWriter, err error, step string) {
	switch {
	case errors.Is(err, service.ErrExpired):
		writePasskeyJSON(w, http.StatusUnauthorized, map[string]string{"redirect": "/login"})
	case errors.Is(err, service.ErrBadCredentials):
		writePasskeyError(w, http.StatusUnauthorized, "That passkey was not accepted.")
	case errors.Is(err, service.ErrPasskeysOff):
		writePasskeyError(w, http.StatusServiceUnavailable, "Passkeys are off on this server.")
	default:
		slog.Error("auth.passkey.login_failed", "step", step, "err", err)
		writePasskeyError(w, http.StatusInternalServerError, "Login failed.")
	}
}

// handlePasskeyRegisterBegin checks the password and answers the creation options.
// in: writer, POST /settings/passkeys/begin with {"password"}. out: JSON options or JSON error.
func (s *Server) handlePasskeyRegisterBegin(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	if !s.localAccount(w, u) {
		return
	}
	var req passkeyRegisterRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPasskeyBody)).Decode(&req); err != nil {
		writePasskeyError(w, http.StatusBadRequest, "Bad request.")
		return
	}
	if !s.confirmPassword(w, u, req.Password) {
		return
	}
	opts, token, expires, err := s.services.Auth.BeginPasskeyRegistration(u.TenantID, u)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrPasskeyLimit):
			writePasskeyError(w, http.StatusConflict, "You already have the most keys an account can hold. Remove one first.")
		case errors.Is(err, service.ErrPasskeysOff):
			writePasskeyError(w, http.StatusServiceUnavailable, "Passkeys are off on this server.")
		default:
			slog.Error("auth.passkey.register_begin_failed", "user_id", u.ID, "err", err)
			writePasskeyError(w, http.StatusInternalServerError, "Could not start passkey setup.")
		}
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: passkeyRegCookie, Value: token, Path: "/settings/passkeys",
		Expires: expires, HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
	slog.Info("auth.passkey.state_change", "from", "off", "to", "pending", "user_id", u.ID, "tenant", u.TenantID)
	writeRawJSON(w, opts)
}

// handlePasskeyRegisterFinish stores the new key after the authenticator answers.
// in: writer, POST /settings/passkeys/finish with {"name","credential"}. out: JSON redirect or JSON error.
func (s *Server) handlePasskeyRegisterFinish(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	if !s.localAccount(w, u) {
		return
	}
	c, err := r.Cookie(passkeyRegCookie)
	if err != nil || c.Value == "" {
		writePasskeyError(w, http.StatusBadRequest, "Setup expired. Start again.")
		return
	}
	s.clearPasskeyRegCookie(w)
	var req passkeyFinishRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxPasskeyBody)).Decode(&req); err != nil || len(req.Credential) == 0 {
		writePasskeyError(w, http.StatusBadRequest, "Bad request.")
		return
	}
	err = s.services.Auth.FinishPasskeyRegistration(u.TenantID, u, c.Value, req.Name, req.Credential)
	switch {
	case err == nil:
	case errors.Is(err, service.ErrExpired):
		writePasskeyError(w, http.StatusBadRequest, "Setup expired. Start again.")
		return
	case errors.Is(err, service.ErrBadCredentials):
		writePasskeyError(w, http.StatusBadRequest, "That key could not be added.")
		return
	case errors.Is(err, service.ErrPasskeyLimit):
		writePasskeyError(w, http.StatusConflict, "You already have the most keys an account can hold. Remove one first.")
		return
	default:
		slog.Error("auth.passkey.register_finish_failed", "user_id", u.ID, "err", err)
		writePasskeyError(w, http.StatusInternalServerError, "Could not save the key.")
		return
	}
	slog.Info("auth.passkey.state_change", "from", "pending", "to", "added", "user_id", u.ID, "tenant", u.TenantID)
	writePasskeyJSON(w, http.StatusOK, map[string]string{"redirect": "/settings?saved=passkey"})
}

// handlePasskeyDelete removes one key after a fresh password check.
// in: writer, POST /settings/passkeys/{id}/delete form (password). out: redirect.
func (s *Server) handlePasskeyDelete(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	if !s.localAccount(w, u) {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "bad key id", http.StatusBadRequest)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ok, err := s.services.Auth.ConfirmPassword(u.TenantID, u.ID, r.PostFormValue("password"))
	if err != nil && !errors.Is(err, service.ErrLoginRateLimited) {
		slog.Error("auth.passkey.reauth_failed", "user_id", u.ID, "err", err)
		http.Error(w, "settings failed", http.StatusInternalServerError)
		return
	}
	if !ok {
		http.Redirect(w, r, "/settings?err=passkey-password", http.StatusSeeOther)
		return
	}
	if err := s.services.Auth.DeletePasskey(u.TenantID, u.ID, id); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			http.Redirect(w, r, "/settings", http.StatusSeeOther)
			return
		}
		slog.Error("auth.passkey.delete_failed", "user_id", u.ID, "err", err)
		http.Error(w, "could not remove the key", http.StatusInternalServerError)
		return
	}
	slog.Info("auth.passkey.state_change", "from", "added", "to", "removed", "user_id", u.ID, "tenant", u.TenantID, "key_id", id)
	http.Redirect(w, r, "/settings?saved=passkey", http.StatusSeeOther)
}

// confirmPassword answers the JSON error itself when the password does not match.
// in: writer, user, password. out: true when it matched.
func (s *Server) confirmPassword(w http.ResponseWriter, u *service.User, password string) bool {
	ok, err := s.services.Auth.ConfirmPassword(u.TenantID, u.ID, password)
	switch {
	case errors.Is(err, service.ErrLoginRateLimited):
		writePasskeyError(w, http.StatusTooManyRequests, "Too many attempts. Wait a few minutes and try again.")
		return false
	case err != nil:
		slog.Error("auth.passkey.reauth_failed", "user_id", u.ID, "err", err)
		writePasskeyError(w, http.StatusInternalServerError, "Could not check your password.")
		return false
	case !ok:
		writePasskeyError(w, http.StatusUnauthorized, "That password is not right.")
		return false
	}
	return true
}

// clearPasskeyRegCookie expires the enroll ceremony cookie.
// in: writer. out: Set-Cookie.
func (s *Server) clearPasskeyRegCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: passkeyRegCookie, Value: "", Path: "/settings/passkeys", MaxAge: -1,
		HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode,
	})
}

// writePasskeyError writes {"error": msg} with status.
// in: writer, status, message. out: JSON response.
func writePasskeyError(w http.ResponseWriter, status int, msg string) {
	writePasskeyJSON(w, status, map[string]string{"error": msg})
}

// writePasskeyJSON writes v as JSON with status.
// in: writer, status, value. out: JSON response.
func writePasskeyJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeRawJSON writes pre-encoded options JSON with 200.
// in: writer, JSON bytes. out: JSON response.
func writeRawJSON(w http.ResponseWriter, b []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(b)
}
