package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/oauth"
	"thesada.app/app/pkg/service"
)

// loadCtx is a short-lived request-scoped context. Callback exchange talks to
// the IdP and should not hang the request indefinitely.
func loadCtx(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 15*time.Second)
}

// handleOIDCStart begins an authorize redirect for the given provider slug.
// `returnTo` is read from the `rt` query param and sanitized; `linking=1`
// tags the flow as a link-to-current-account rather than a sign-in. Linking
// requires an existing session.
//
// Route: GET /auth/oidc/{slug}/start
func (s *Server) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if slug == "" {
		http.NotFound(w, r)
		return
	}

	ctx, cancel := loadCtx(r)
	defer cancel()

	tenantHint := ""
	if sess := authmw.CurrentSession(r); sess != nil && sess.User != nil {
		tenantHint = sess.User.TenantID
	}

	p, err := s.services.OAuth.LoadProviderBySlug(ctx, slug, tenantHint, s.cfg.BaseURL)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("oidc provider load failed", "slug", slug, "err", err)
		http.Error(w, "provider unavailable", http.StatusBadGateway)
		return
	}

	opts := oauth.StartOpts{ReturnTo: r.URL.Query().Get("rt")}
	if r.URL.Query().Get("linking") == "1" {
		u := authmw.CurrentUser(r)
		if u == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		opts.LinkingUserID = &u.ID
	}

	authURL, err := s.services.OAuth.StartProvider(ctx, p, opts)
	if err != nil {
		slog.Error("oidc start failed", "slug", slug, "err", err)
		http.Error(w, "oidc start failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback completes the authorize flow: exchange the code, verify
// the id_token, resolve claims, then either sign the user in (existing link or
// email match) or link a new identity to the current session (linking flow).
//
// Route: GET /auth/oidc/{slug}/callback
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	if slug == "" || code == "" || state == "" {
		if errParam := r.URL.Query().Get("error"); errParam != "" {
			s.render(w, r, "login.html", map[string]interface{}{
				"Error": "Sign-in cancelled by identity provider (" + errParam + ").",
			})
			return
		}
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}

	ctx, cancel := loadCtx(r)
	defer cancel()

	pending, err := s.services.OAuth.LookupState(ctx, state)
	if err != nil {
		slog.Warn("oidc state unknown", "slug", slug, "err", err)
		s.render(w, r, "login.html", map[string]interface{}{
			"Error": "Sign-in link expired, try again.",
		})
		return
	}

	// Load the exact provider the auth request was started against. Resolving
	// by stored id (not slug+tenant) keeps /start and /callback symmetric: a
	// slug re-resolve with an empty tenant hint returns the lowest-id tenant's
	// provider, which 400s as a state/provider mismatch when the session's
	// tenant isn't that one.
	p, err := s.services.OAuth.LoadProviderByID(ctx, pending.ProviderID, s.cfg.BaseURL)
	if err != nil {
		slog.Error("oidc provider reload failed on callback", "slug", slug, "provider_id", pending.ProviderID, "err", err)
		http.Error(w, "provider unavailable", http.StatusBadGateway)
		return
	}

	claims, err := p.Exchange(ctx, code, pending)
	if err != nil {
		slog.Error("oidc exchange failed", "slug", slug, "err", err)
		s.render(w, r, "login.html", map[string]interface{}{
			"Error": "Sign-in with " + p.Row.DisplayName + " failed.",
		})
		return
	}

	// --- link-to-existing-session flow ----------------------------------
	if pending.LinkingUserID != nil {
		if err := s.services.OAuth.LinkIdentity(ctx, *pending.LinkingUserID, p.Row.ID, claims.Subject, claims.Email); err != nil {
			if errors.Is(err, service.ErrConflict) {
				http.Redirect(w, r, "/settings?err=identity_taken", http.StatusFound)
				return
			}
			slog.Error("oidc link failed", "user_id", *pending.LinkingUserID, "err", err)
			http.Error(w, "link failed", http.StatusInternalServerError)
			return
		}
		slog.Info("oauth.identity.state_change",
			"from", "unlinked", "to", "linked",
			"user_id", *pending.LinkingUserID, "provider", p.Row.Slug, "trigger", "settings_link")
		http.Redirect(w, r, safeReturn(pending.ReturnTo, "/settings"), http.StatusFound)
		return
	}

	// --- sign-in flow: existing link first ------------------------------
	if u, err := s.services.OAuth.FindUserByIdentity(ctx, p.Row.ID, claims.Subject); err == nil {
		s.startSession(w, r, u, "oidc")
		http.Redirect(w, r, safeReturn(pending.ReturnTo, "/devices"), http.StatusFound)
		return
	} else if !errors.Is(err, service.ErrNotFound) {
		slog.Error("oidc identity lookup failed", "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	// --- email-match auto-link (only when the id_token marked email verified) --
	// Scoped to the provider's tenant inside FindUserByEmail: a global provider
	// never auto-links by email, a per-tenant provider matches only its own
	// tenant. Prevents binding the session to the wrong tenant's user when the
	// same email exists in several tenants.
	if claims.Email != "" && claims.EmailVerified {
		if u, err := s.services.OAuth.FindUserByEmail(ctx, p.Row.TenantID, claims.Email); err == nil {
			if err := s.services.OAuth.LinkIdentity(ctx, u.ID, p.Row.ID, claims.Subject, claims.Email); err == nil {
				slog.Info("oauth.identity.state_change",
					"from", "unlinked", "to", "linked",
					"user_id", u.ID, "tenant", u.TenantID, "provider", p.Row.Slug, "trigger", "email_match")
				s.startSession(w, r, u, "oidc")
				http.Redirect(w, r, safeReturn(pending.ReturnTo, "/devices"), http.StatusFound)
				return
			}
		} else if !errors.Is(err, service.ErrNotFound) {
			slog.Error("oidc email lookup failed", "err", err)
		}
	}

	// No local account, no auto-provision (deferred to follow-up).
	s.render(w, r, "login.html", map[string]interface{}{
		"Error": "No Thesada account matches this " + p.Row.DisplayName + " identity. Sign in locally, then link it from settings.",
	})
}

// handleIdentityUnlink removes a (provider, subject) link from the current user.
// Guards against removing the user's only credential: if they have no password
// and would be left with zero identities, the delete is refused.
//
// Route: POST /settings/oauth/{id}/unlink
func (s *Server) handleIdentityUnlink(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	if u == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	ctx, cancel := loadCtx(r)
	defer cancel()

	identities, err := s.services.OAuth.ListIdentitiesForUser(ctx, u.TenantID, u.ID)
	if err != nil {
		slog.Error("oidc list identities failed", "err", err)
		http.Error(w, "unlink failed", http.StatusInternalServerError)
		return
	}
	hasPassword, err := s.services.Auth.HasPassword(u.TenantID, u.ID)
	if err != nil {
		slog.Error("oidc check password failed", "err", err)
		http.Error(w, "unlink failed", http.StatusInternalServerError)
		return
	}
	if !hasPassword && len(identities) <= 1 {
		http.Redirect(w, r, "/settings?err=last_credential", http.StatusFound)
		return
	}

	if err := s.services.OAuth.DeleteIdentity(ctx, u.TenantID, u.ID, id); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			http.Redirect(w, r, "/settings?err=identity_not_found", http.StatusFound)
			return
		}
		slog.Error("oidc unlink failed", "err", err)
		http.Error(w, "unlink failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/settings#sso", http.StatusFound)
}

// safeReturn vets a persisted ReturnTo against open-redirect misuse, falling
// back to the supplied default when the stored path is hostile.
func safeReturn(path, fallback string) string {
	if oauth.IsSafeReturnTo(path) {
		return path
	}
	return fallback
}
