// Auto-extracted from service.go on 2026-05-05.
// Lives in package service. Imports cleaned by goimports.
package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// ---------------------------------------------------------------------------
// TenantService - tenant CRUD + slug validation + in-memory slug cache.
// ---------------------------------------------------------------------------

// TenantService handles the tenants table and maintains a small in-memory
// slug-existence cache so that the MQTT ingest hot path does not hit the db
// on every incoming message. Cache is refreshed on Create/Delete and on a
// background Refresh() call at startup.
//
// RLS: the tenants table deliberately has NO row-level security -
// it is cross-tenant by definition (0016 leaves it ungated). Every DB
// method here is therefore a cross-tenant operation and runs under
// db.WithAdminAudit on the BYPASSRLS pool so the access is audit-logged in
// one place. CountMembers reads users + devices (which DO have RLS) across
// the tenant boundary for the super-admin dashboard - same treatment.
type TenantService struct {
	cfg     *config.Config
	pools   db.Pools
	secrets *SecretService // provisions the per-tenant DEK at Create; nil-safe when the feature is off

	mu    sync.RWMutex
	slugs map[string]struct{}
}

// Tenant is the exported shape of a tenants row.
type Tenant struct {
	ID          string // slug, immutable, also the PK
	DisplayName string
	UUID        uuid.UUID // secondary key for future external refs
	CreatedAt   time.Time
}

// reservedSlugs mirrors the database CHECK constraint so we can reject at the
// handler layer with a friendly error instead of letting the db throw.
var reservedSlugs = map[string]bool{
	"admin": true, "system": true, "api": true, "provision": true,
	"status": true, "info": true, "sensor": true, "alert": true,
	"cli": true, "cmd": true, "homeassistant": true,
}

// slugPattern mirrors the tenants_id_slug_format db CHECK.
var slugPattern = regexp.MustCompile(`^[a-z0-9-]{3,32}$`)

// ErrInvalidSlug means the proposed slug did not pass the regex.
var ErrInvalidSlug = errors.New("slug must match [a-z0-9-]{3,32}")

// ErrReservedSlug means the proposed slug is on the reserved list.
var ErrReservedSlug = errors.New("slug is reserved")

// ErrSlugTaken means a tenant with this slug already exists.
var ErrSlugTaken = errors.New("slug already in use")

// ErrTenantProtected means the caller tried to delete a tenant that must not
// be removed (default, or the acting super-admin's current tenant).
var ErrTenantProtected = errors.New("tenant is protected")

// ValidateSlug runs the regex and reserved-slug checks with no db round-trip.
// in: proposed slug. out: nil on ok, ErrInvalidSlug / ErrReservedSlug.
func ValidateSlug(slug string) error {
	if !slugPattern.MatchString(slug) {
		return ErrInvalidSlug
	}
	if reservedSlugs[slug] {
		return ErrReservedSlug
	}
	return nil
}

// Refresh loads every tenant slug into the in-memory cache. Call at startup
// and after any external schema change. Create/Delete update the cache in
// place so manual calls should be rare.
// out: error on db failure.
func (s *TenantService) Refresh() error {
	ctx := context.Background()
	fresh := make(map[string]struct{}, 8)
	err := db.WithAdminAudit(ctx, s.pools.Admin, "tenant.refresh", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM tenants`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			fresh[id] = struct{}{}
		}
		return rows.Err()
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.slugs = fresh
	s.mu.Unlock()
	return nil
}

// ExistsBySlug returns true if the slug is a known tenant. Hot-path lookup
// used by MQTT ingest to reject unknown 4-tier topic prefixes cheaply.
// in: slug. out: true if cached.
func (s *TenantService) ExistsBySlug(slug string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.slugs[slug]
	return ok
}

// List returns every tenant in slug order.
// out: []Tenant, error.
func (s *TenantService) List() ([]Tenant, error) {
	const query = `SELECT id, display_name, uuid, created_at FROM tenants ORDER BY id`
	ctx := context.Background()
	var out []Tenant
	err := db.WithAdminAudit(ctx, s.pools.Admin, "tenant.list", func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t Tenant
			if err := rows.Scan(&t.ID, &t.DisplayName, &t.UUID, &t.CreatedAt); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Get returns a single tenant by slug or ErrNotFound.
// in: slug. out: *Tenant, error.
func (s *TenantService) Get(slug string) (*Tenant, error) {
	const query = `SELECT id, display_name, uuid, created_at FROM tenants WHERE id = $1`
	ctx := context.Background()
	var t Tenant
	err := db.WithAdminAudit(ctx, s.pools.Admin, "tenant.get", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, slug).Scan(
			&t.ID, &t.DisplayName, &t.UUID, &t.CreatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// Create inserts a new tenant row after app-side slug validation. The db
// CHECK constraints are a second line of defense: if the app-side validation
// ever drifts from the regex/reserved list, the constraint still rejects.
// in: slug, display_name. out: *Tenant, error.
func (s *TenantService) Create(slug, displayName string) (*Tenant, error) {
	if err := ValidateSlug(slug); err != nil {
		return nil, err
	}
	if displayName == "" {
		displayName = slug
	}
	const query = `
		INSERT INTO tenants (id, display_name) VALUES ($1, $2)
		RETURNING id, display_name, uuid, created_at`
	ctx := context.Background()
	var t Tenant
	err := db.WithAdminAudit(ctx, s.pools.Admin, "tenant.create", func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, query, slug, displayName).Scan(
			&t.ID, &t.DisplayName, &t.UUID, &t.CreatedAt); err != nil {
			return err
		}
		// Seal the per-tenant device-config-secrets DEK in the same tx so a
		// tenant never exists without one while the feature is on. No-op when
		// off. Runs on the admin (BYPASSRLS) pool, so the tenant_dek RLS policy
		// is bypassed - correct, this is the row that policy will later gate.
		if s.secrets != nil {
			if err := s.secrets.ProvisionTenantDEKTx(ctx, tx, slug); err != nil {
				return fmt.Errorf("provision tenant DEK: %w", err)
			}
		}
		return nil
	})
	if err != nil {
		// pg unique_violation = 23505. Wrap as ErrSlugTaken for the handler.
		if strings.Contains(err.Error(), "tenants_pkey") {
			return nil, ErrSlugTaken
		}
		return nil, err
	}
	s.mu.Lock()
	if s.slugs == nil {
		s.slugs = make(map[string]struct{})
	}
	s.slugs[slug] = struct{}{}
	s.mu.Unlock()
	return &t, nil
}

// CountMembers returns (user_count, device_count) for a single tenant slug.
// Used by the super-admin dashboard. Zero on empty tenant; errors propagate.
// in: slug. out: user count, device count, error.
func (s *TenantService) CountMembers(slug string) (int, int, error) {
	ctx := context.Background()
	var users, devices int
	err := db.WithAdminAudit(ctx, s.pools.Admin, "tenant.count_members", func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM users WHERE tenant_id = $1`, slug).Scan(&users); err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM devices WHERE tenant_id = $1`, slug).Scan(&devices)
	})
	if err != nil {
		return 0, 0, err
	}
	return users, devices, nil
}

// Delete removes a tenant by slug. Protected slugs: the 'default' bootstrap
// tenant and whatever tenant the caller is currently operating as (prevents
// a super-admin from deleting the seat they are sitting on).
// in: slug, callerTenantID. out: error (ErrTenantProtected on guard fail).
func (s *TenantService) Delete(slug, callerTenantID string) error {
	if slug == "default" {
		return ErrTenantProtected
	}
	if slug == callerTenantID {
		return ErrTenantProtected
	}
	ctx := context.Background()
	if err := db.WithAdminAudit(ctx, s.pools.Admin, "tenant.delete", func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, slug)
		return err
	}); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.slugs, slug)
	s.mu.Unlock()
	return nil
}
