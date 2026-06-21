package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/oauth"
)

// ErrConflict is returned by LinkIdentity when (provider, subject) is already
// linked to a different local user. Other packages don't need to distinguish
// unique-violation vs other DB errors for any other operation here.
var ErrConflict = errors.New("conflict")

// OAuthService owns oauth_providers + user_oauth_identities. It is deliberately
// small: providers are cached on first load via oauth.LoadProvider (which runs
// OIDC discovery), identities are straight CRUD. Actual OIDC flow logic lives
// in pkg/oauth.
//
// RLS: oauth_providers has a direct tenant_id policy;
// user_oauth_identities is transitive via user_id -> users.tenant_id.
// Tenant-scoped reads (provider list for a known tenant, a user's own
// identities) run under db.WithTenant. The OIDC sign-in flow itself -
// anonymous provider lookup, identity resolution, the callback link path -
// runs before tenant context exists and goes through db.WithAdminAudit on
// the BYPASSRLS pool, like the session and magic-link paths.
type OAuthService struct {
	cfg   *config.Config
	pools db.Pools
}

// NewOAuthService constructs the service. Stored on Services bundle in service.New.
func NewOAuthService(cfg *config.Config, pools db.Pools) *OAuthService {
	return &OAuthService{cfg: cfg, pools: pools}
}

// ProviderSummary is what the login page + settings UI render. Omits secrets
// and issuer URL; those stay on the server.
type ProviderSummary struct {
	ID          uuid.UUID
	Slug        string
	DisplayName string
}

// ListEnabledProvidersForTenant returns providers that are either global
// (tenant_id NULL) or scoped to the given tenant, enabled, kind 'oidc'.
// Tenant-scoped through WithTenant.
// in: ctx, tenantID. out: []ProviderSummary, error.
func (s *OAuthService) ListEnabledProvidersForTenant(ctx context.Context, tenantID string) ([]ProviderSummary, error) {
	const query = `
		SELECT id, slug, display_name
		FROM oauth_providers
		WHERE enabled = true
		  AND (tenant_id IS NULL OR tenant_id = $1)
		ORDER BY display_name`
	var out []ProviderSummary
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p ProviderSummary
			if err := rows.Scan(&p.ID, &p.Slug, &p.DisplayName); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListEnabledProvidersForLogin is the unauthenticated variant - used by
// the login page when we don't yet know which tenant the user will hit.
// One button per slug; migration 0015 cross-joined providers per tenant,
// so the same Kanidm config now exists N times (once per tenant) and we
// must dedupe to avoid rendering "Sign in with Kanidm" once per tenant.
// DISTINCT ON (slug) with a stable ORDER BY id picks the same per-tenant
// row on every call so the provider_id seen by LoadProviderBySlug stays
// consistent (and existing user_oauth_identities links keep resolving).
//
// Cross-tenant BY DESIGN - the login page has no tenant yet. Runs under
// WithAdminAudit.
// in: ctx. out: []ProviderSummary, error.
func (s *OAuthService) ListEnabledProvidersForLogin(ctx context.Context) ([]ProviderSummary, error) {
	const query = `
		SELECT DISTINCT ON (slug) id, slug, display_name
		FROM oauth_providers
		WHERE enabled = true AND client_secret <> ''
		ORDER BY slug, id`
	var out []ProviderSummary
	err := db.WithAdminAudit(ctx, s.pools.Admin, "oauth.list_providers_for_login", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var p ProviderSummary
			if err := rows.Scan(&p.ID, &p.Slug, &p.DisplayName); err != nil {
				return err
			}
			out = append(out, p)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// LoadProviderBySlug fetches + OIDC-discovers a provider by slug.
// Returns ErrNotFound if slug is unknown or every matching row is
// disabled. Tenant scoping after migration 0015 (oauth_providers became
// per-tenant): when tenantHint is empty (anonymous login flow) the
// query matches any tenant's row, ORDER BY id keeping the pick stable
// across calls so the provider_id flowing into LinkIdentity /
// FindUserByIdentity stays consistent. When tenantHint is set
// (link-to-existing-session flow) the query restricts to that tenant.
//
// Runs under WithAdminAudit: tenantHint may be empty (anonymous login),
// and even when set the SQL self-restricts via the $2 clause - so the
// BYPASSRLS pool is correct for both shapes of this sign-in-infra call.
// in: ctx, slug, tenantHint, redirectBase. out: *oauth.Provider, error.
func (s *OAuthService) LoadProviderBySlug(ctx context.Context, slug, tenantHint, redirectBase string) (*oauth.Provider, error) {
	const query = `
		SELECT id, tenant_id, slug, display_name, kind, issuer_url, client_id, client_secret, scopes
		FROM oauth_providers
		WHERE slug = $1 AND enabled = true AND client_secret <> ''
		  AND ($2 = '' OR tenant_id = $2)
		ORDER BY id
		LIMIT 1`
	var row oauth.ProviderRow
	err := db.WithAdminAudit(ctx, s.pools.Admin, "oauth.load_provider_by_slug", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, slug, tenantHint).Scan(
			&row.ID, &row.TenantID, &row.Slug, &row.DisplayName, &row.Kind, &row.IssuerURL, &row.ClientID, &row.ClientSecret, &row.Scopes)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return oauth.LoadProvider(ctx, row, redirectBase)
}

// LoadProviderByID resolves a single provider by its primary key. The OIDC
// callback uses this instead of LoadProviderBySlug: the stored auth request
// already carries the exact provider id chosen at /start, so re-resolving by
// slug (which, with an empty tenant hint, returns ORDER BY id LIMIT 1) could
// load a different tenant's provider for the same slug and 400 as a
// state/provider mismatch.
// in: ctx, id, redirectBase. out: *oauth.Provider, error.
func (s *OAuthService) LoadProviderByID(ctx context.Context, id uuid.UUID, redirectBase string) (*oauth.Provider, error) {
	const query = `
		SELECT id, tenant_id, slug, display_name, kind, issuer_url, client_id, client_secret, scopes
		FROM oauth_providers
		WHERE id = $1 AND enabled = true AND client_secret <> ''
		LIMIT 1`
	var row oauth.ProviderRow
	err := db.WithAdminAudit(ctx, s.pools.Admin, "oauth.load_provider_by_id", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, id).Scan(
			&row.ID, &row.TenantID, &row.Slug, &row.DisplayName, &row.Kind, &row.IssuerURL, &row.ClientID, &row.ClientSecret, &row.Scopes)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return oauth.LoadProvider(ctx, row, redirectBase)
}

// IdentityRow is a denormalized view of user_oauth_identities joined with the
// provider. Used by the settings page "connected accounts" list.
type IdentityRow struct {
	ID            uuid.UUID
	ProviderID    uuid.UUID
	ProviderSlug  string
	ProviderLabel string
	Subject       string
	Email         *string
	CreatedAt     time.Time
	LastLoginAt   *time.Time
}

// ListIdentitiesForUser returns every external identity linked to user_id.
// Tenant-scoped through WithTenant: user_oauth_identities is RLS-policed
// transitive via user_id -> users.tenant_id.
// in: ctx, tenantID, userID. out: []IdentityRow, error.
func (s *OAuthService) ListIdentitiesForUser(ctx context.Context, tenantID string, userID uuid.UUID) ([]IdentityRow, error) {
	const query = `
		SELECT i.id, i.provider_id, p.slug, p.display_name, i.subject, i.email, i.created_at, i.last_login_at
		FROM user_oauth_identities i
		JOIN oauth_providers p ON p.id = i.provider_id
		WHERE i.user_id = $1
		ORDER BY p.display_name, i.created_at`
	var out []IdentityRow
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r IdentityRow
			if err := rows.Scan(&r.ID, &r.ProviderID, &r.ProviderSlug, &r.ProviderLabel, &r.Subject, &r.Email, &r.CreatedAt, &r.LastLoginAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// FindUserByIdentity resolves an external (provider, subject) pair to
// the local user and records last_login_at on the identity row. Matches
// across every per-tenant copy of the provider via slug-equality so a
// post-0015 deployment, where the same Kanidm config exists as N rows
// (one per tenant) each with its own UUID, still resolves to the user's
// original identity link regardless of which per-tenant row
// LoadProviderBySlug happened to pick on this request. Returns
// ErrNotFound if no link exists.
//
// Cross-tenant BY DESIGN - the OIDC callback resolves identity -> user,
// which is what determines the tenant. Runs under WithAdminAudit.
// in: ctx, providerID (any per-tenant copy with the desired slug), subject.
// out: *User, error.
func (s *OAuthService) FindUserByIdentity(ctx context.Context, providerID uuid.UUID, subject string) (*User, error) {
	const lookup = `
		SELECT u.id, u.tenant_id, u.email, u.display_name, u.telegram_chat_id, u.is_admin, u.is_super_admin, u.created_at, u.last_login_at
		FROM user_oauth_identities i
		JOIN oauth_providers p ON p.id = i.provider_id
		JOIN users u ON u.id = i.user_id
		WHERE p.slug = (SELECT slug FROM oauth_providers WHERE id = $1)
		  AND i.subject = $2
		LIMIT 1`
	const touch = `
		UPDATE user_oauth_identities SET last_login_at = now()
		 WHERE subject = $2
		   AND provider_id IN (
		       SELECT id FROM oauth_providers
		        WHERE slug = (SELECT slug FROM oauth_providers WHERE id = $1)
		   )`
	var u User
	err := db.WithAdminAudit(ctx, s.pools.Admin, "oauth.find_user_by_identity", func(tx pgx.Tx) error {
		if scanErr := tx.QueryRow(ctx, lookup, providerID, subject).Scan(
			&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt); scanErr != nil {
			return scanErr
		}
		_, _ = tx.Exec(ctx, touch, providerID, subject)
		return nil
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// LinkIdentity attaches an external identity to an existing user. The
// (provider, subject) UNIQUE constraint enforces 1:1 mapping to local users.
//
// Cross-tenant BY DESIGN - called from the OIDC callback, which has only a
// pending-request record (no tenant context). Runs under WithAdminAudit.
// in: ctx, userID, providerID, subject, email. out: error (ErrConflict on dup).
func (s *OAuthService) LinkIdentity(ctx context.Context, userID, providerID uuid.UUID, subject, email string) error {
	var emailArg any
	if email != "" {
		emailArg = email
	}
	err := db.WithAdminAudit(ctx, s.pools.Admin, "oauth.link_identity", func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx, `
			INSERT INTO user_oauth_identities (user_id, provider_id, subject, email, last_login_at)
			VALUES ($1, $2, $3, $4, now())
		`, userID, providerID, subject, emailArg)
		return execErr
	})
	if err != nil {
		if isUniqueViolation(err) {
			return ErrConflict
		}
		return err
	}
	return nil
}

// DeleteIdentity removes a link. Only the owning user may unlink; the caller
// is expected to verify ownership before calling. Returns ErrNotFound if the
// row did not exist (or did not belong to userID). Tenant-scoped through
// WithTenant - this is the authenticated settings-page unlink path.
// in: ctx, tenantID, userID, identityID. out: error.
func (s *OAuthService) DeleteIdentity(ctx context.Context, tenantID string, userID, identityID uuid.UUID) error {
	var affected int64
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		tag, execErr := tx.Exec(ctx, `
			DELETE FROM user_oauth_identities WHERE id = $1 AND user_id = $2
		`, identityID, userID)
		if execErr != nil {
			return execErr
		}
		affected = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrNotFound
	}
	return nil
}

// StartProvider delegates to oauth.Start and persists the pending request
// in the OIDC flow. Runs on the BYPASSRLS pool: the oauth_auth_requests
// INSERT happens before a session exists, so there is no app.tenant_id GUC
// to satisfy its RLS policy. pkg/oauth itself is not RLS-aware; routing it
// through pools.Admin keeps the sign-in flow working until pkg/oauth gets
// its own conversion.
// in: ctx, *oauth.Provider, opts. out: authorize URL, error.
func (s *OAuthService) StartProvider(ctx context.Context, p *oauth.Provider, opts oauth.StartOpts) (string, error) {
	return p.Start(ctx, s.pools.Admin, opts)
}

// LookupState delegates to oauth.LookupState. Runs on the BYPASSRLS pool
// for the same reason as StartProvider - the OIDC callback resolves the
// pending request before any tenant context exists.
// in: ctx, state string. out: *oauth.PendingRequest, error (oauth.ErrUnknownState).
func (s *OAuthService) LookupState(ctx context.Context, state string) (*oauth.PendingRequest, error) {
	return oauth.LookupState(ctx, s.pools.Admin, state)
}

// FindUserByEmail is a local lookup used when the OIDC callback has no existing
// (provider, subject) link but the provider emitted a verified email that may
// match a local user, so the callback can auto-link.
//
// Scoped to the provider's tenant. Email is only UNIQUE per (tenant_id, email),
// so an unscoped match could resolve to the wrong tenant's user when the same
// address exists in several tenants - a cross-tenant account-takeover edge. A
// per-tenant provider scopes the match to its own tenant (at most one row). A
// global provider (providerTenantID nil) has no tenant to scope to, so it never
// auto-links by email - those users must link manually from settings. Runs
// under WithAdminAudit because the callback has no tenant context of its own.
// in: ctx, the provider's tenant_id (nil for global), email. out: *User, error
// (ErrNotFound when no scoped match, or always for a global provider).
func (s *OAuthService) FindUserByEmail(ctx context.Context, providerTenantID *string, email string) (*User, error) {
	if providerTenantID == nil || *providerTenantID == "" {
		return nil, ErrNotFound
	}
	var u User
	err := db.WithAdminAudit(ctx, s.pools.Admin, "oauth.find_user_by_email", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT id, tenant_id, email, display_name, telegram_chat_id, is_admin, is_super_admin, created_at, last_login_at
			FROM users
			WHERE email = $1 AND tenant_id = $2
		`, email, *providerTenantID).Scan(&u.ID, &u.TenantID, &u.Email, &u.DisplayName, &u.TelegramChatID, &u.IsAdmin, &u.IsSuperAdmin, &u.CreatedAt, &u.LastLoginAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// isUniqueViolation mirrors pgx's error check for unique-constraint failures
// without pulling in pgconn directly at every call site.
// in: error. out: bool.
func isUniqueViolation(err error) bool {
	type sqlState interface{ SQLState() string }
	var s sqlState
	if errors.As(err, &s) {
		return s.SQLState() == "23505"
	}
	return false
}
