// Package oauth implements the OIDC / OAuth2 client side of thesada-app's
// hybrid auth. Provider config is loaded from the oauth_providers
// table at request time so toggles + secret rotations take effect without a
// redeploy.
//
// The package intentionally does not touch the session or user layer - those
// decisions belong to the service layer. Public surface:
//
//	type Provider         // resolved OIDC config + verifier
//	type Claims           // subset of id_token + userinfo we consume
//	LoadProvider(...)     // DB row -> *Provider (does OIDC discovery)
//	(*Provider) Start(...)    // build authorize URL + store state
//	(*Provider) Exchange(...) // handle callback, return Claims
//
// The only OIDC library dependency is github.com/coreos/go-oidc/v3. PKCE,
// nonce, and state correlation are enforced on every flow.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/oauth2"
)

// authRequestTTL bounds how long a pending authorize flow stays valid. Long
// enough for a slow user on a bad network to complete the IdP round-trip;
// short enough to make replay attacks uninteresting. Matches Kanidm's own
// authorize code TTL of 10 min.
const authRequestTTL = 10 * time.Minute

// ProviderRow mirrors an oauth_providers DB row. Services load these and
// pass to LoadProvider; this package does not query the table itself.
type ProviderRow struct {
	ID           uuid.UUID
	TenantID     *string // nil for a global (cross-tenant) provider; set for a per-tenant copy
	Slug         string
	DisplayName  string
	Kind         string
	IssuerURL    string
	ClientID     string
	ClientSecret string
	Scopes       []string
}

// Provider is a resolved, ready-to-use OIDC client. One per ProviderRow.
// Safe to cache across requests; the underlying oidc.Provider holds a
// refreshing JWKS fetcher.
type Provider struct {
	Row      ProviderRow
	oidc     *oidc.Provider
	verifier *oidc.IDTokenVerifier
	cfg      oauth2.Config
}

// Claims is the subset of ID-token + userinfo fields we consume.
type Claims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	PreferredUser string   `json:"preferred_username"`
	Groups        []string `json:"groups"`
}

// LoadProvider runs OIDC discovery against row.IssuerURL and constructs a
// ready Provider. redirectBase is the app's public base URL
// (e.g. "https://app.thesada.app"); the per-provider callback is
// derived as redirectBase + "/auth/oidc/" + slug + "/callback".
// in: ctx, row, redirectBase. out: *Provider, error.
func LoadProvider(ctx context.Context, row ProviderRow, redirectBase string) (*Provider, error) {
	if row.Kind != "oidc" {
		return nil, fmt.Errorf("oauth: provider kind %q not implemented", row.Kind)
	}
	issuer, err := oidc.NewProvider(ctx, row.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("oauth: discover %s: %w", row.IssuerURL, err)
	}
	cfg := oauth2.Config{
		ClientID:     row.ClientID,
		ClientSecret: row.ClientSecret,
		Endpoint:     issuer.Endpoint(),
		RedirectURL:  strings.TrimRight(redirectBase, "/") + "/auth/oidc/" + row.Slug + "/callback",
		Scopes:       row.Scopes,
	}
	return &Provider{
		Row:      row,
		oidc:     issuer,
		verifier: issuer.Verifier(&oidc.Config{ClientID: row.ClientID}),
		cfg:      cfg,
	}, nil
}

// StartOpts controls the authorize-redirect initiation.
type StartOpts struct {
	// ReturnTo is where the user should land after successful callback.
	// Must be a relative path starting with "/". "/" is the default.
	ReturnTo string
	// LinkingUserID, if non-nil, tags this flow as "user is linking a new
	// identity to their existing account" rather than "user is signing in".
	LinkingUserID *uuid.UUID
}

// Start generates state + nonce + PKCE verifier, persists them in
// oauth_auth_requests, and returns the authorize URL the caller should
// redirect to. Expired rows are swept best-effort on every insert.
// in: ctx, db pool, StartOpts. out: authorize URL, error.
func (p *Provider) Start(ctx context.Context, db *pgxpool.Pool, opts StartOpts) (string, error) {
	state, err := randomURLSafe(32)
	if err != nil {
		return "", fmt.Errorf("oauth: state: %w", err)
	}
	nonce, err := randomURLSafe(32)
	if err != nil {
		return "", fmt.Errorf("oauth: nonce: %w", err)
	}
	verifier, err := randomURLSafe(64)
	if err != nil {
		return "", fmt.Errorf("oauth: pkce: %w", err)
	}
	challenge := pkceChallenge(verifier)

	returnTo := opts.ReturnTo
	if !IsSafeReturnTo(returnTo) {
		returnTo = "/"
	}

	// Best-effort sweep - no error propagated if it fails.
	_, _ = db.Exec(ctx, `DELETE FROM oauth_auth_requests WHERE expires_at < now()`)

	_, err = db.Exec(ctx, `
		INSERT INTO oauth_auth_requests (state, provider_id, nonce, pkce_verifier, return_to, linking_user_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`, state, p.Row.ID, nonce, verifier, returnTo, opts.LinkingUserID, time.Now().Add(authRequestTTL))
	if err != nil {
		return "", fmt.Errorf("oauth: persist state: %w", err)
	}

	return p.cfg.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	), nil
}

// PendingRequest is the resolved row backing an in-flight authorize flow.
// Callers get this from ExchangeContext before redirecting to ReturnTo.
type PendingRequest struct {
	ProviderID    uuid.UUID
	Nonce         string
	PKCEVerifier  string
	ReturnTo      string
	LinkingUserID *uuid.UUID
}

// ErrUnknownState indicates the state string did not match a persisted
// auth request (expired, forged, or already consumed).
var ErrUnknownState = errors.New("oauth: unknown or expired state")

// LookupState consumes a pending auth-request row and returns its context.
// The row is deleted on success so state is single-use.
// in: ctx, db, state string. out: PendingRequest, error.
func LookupState(ctx context.Context, db *pgxpool.Pool, state string) (*PendingRequest, error) {
	var pr PendingRequest
	var expiresAt time.Time
	err := db.QueryRow(ctx, `
		DELETE FROM oauth_auth_requests WHERE state = $1
		RETURNING provider_id, nonce, pkce_verifier, return_to, linking_user_id, expires_at
	`, state).Scan(&pr.ProviderID, &pr.Nonce, &pr.PKCEVerifier, &pr.ReturnTo, &pr.LinkingUserID, &expiresAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrUnknownState
	}
	if err != nil {
		return nil, err
	}
	if time.Now().After(expiresAt) {
		return nil, ErrUnknownState
	}
	return &pr, nil
}

// Exchange swaps the authorization code for tokens, verifies the id_token
// (signature, audience, issuer, nonce), fetches userinfo if email is missing
// from the id_token, and returns the resolved Claims.
// in: ctx, code, pending (from LookupState). out: *Claims, error.
func (p *Provider) Exchange(ctx context.Context, code string, pending *PendingRequest) (*Claims, error) {
	tok, err := p.cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", pending.PKCEVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("oauth: exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return nil, errors.New("oauth: missing id_token in token response")
	}
	idTok, err := p.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("oauth: verify id_token: %w", err)
	}
	if idTok.Nonce != pending.Nonce {
		return nil, errors.New("oauth: nonce mismatch")
	}

	var c Claims
	if err := idTok.Claims(&c); err != nil {
		return nil, fmt.Errorf("oauth: parse id_token claims: %w", err)
	}

	// Fall back to userinfo when the id_token omitted email (Kanidm does
	// include email in the id_token for scope=email, but not every IdP
	// does; this keeps us portable).
	if c.Email == "" {
		ui, err := p.oidc.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err == nil {
			_ = ui.Claims(&c)
			if c.Email == "" {
				c.Email = ui.Email
			}
		}
	}

	if c.Subject == "" {
		c.Subject = idTok.Subject
	}
	if c.Subject == "" {
		return nil, errors.New("oauth: id_token missing subject")
	}

	c.Email = strings.ToLower(strings.TrimSpace(c.Email))
	return &c, nil
}

// --- internal helpers --------------------------------------------------

// randomURLSafe returns n random bytes base64url-encoded without padding.
// in: n. out: string, error.
func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// pkceChallenge derives the S256 challenge string from a verifier.
// in: verifier. out: challenge.
func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// IsSafeReturnTo rejects absolute or scheme-bearing return_to values that
// could be abused for open-redirect attacks. Callers should apply this
// before trusting the stored ReturnTo after callback.
// in: path. out: bool.
func IsSafeReturnTo(path string) bool {
	// Reject "//host" and "/\host": browsers may read the second char as the
	// authority separator and leave the origin.
	if path == "" || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.HasPrefix(path, "/\\") {
		return false
	}
	if _, err := url.Parse(path); err != nil {
		return false
	}
	return true
}
