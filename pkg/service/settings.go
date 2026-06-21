// Auto-extracted from service.go on 2026-05-05.
// Lives in package service. Imports cleaned by goimports.
package service

import (
	"context"
	"encoding/json"
	"sync"

	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// ---------------------------------------------------------------------------
// SettingsService - read-through cache for the settings key/value table.
// ---------------------------------------------------------------------------

// SettingsService caches the settings table in memory so that hot-path reads
// (header dropdown, middleware) do not hit the db per request. Writes go
// through Set which updates both the row and the cache.
type SettingsService struct {
	cfg   *config.Config
	pools db.Pools

	mu    sync.RWMutex
	cache map[string]json.RawMessage // key = tenantID + "/" + key
}

// settingsCacheKey formats the composite cache key.
// in: tenant_id, setting key. out: map key.
func settingsCacheKey(tenantID, key string) string {
	return tenantID + "/" + key
}

// Refresh loads every settings row across every tenant into the cache.
// Cross-tenant read by design - the cache holds rows for every tenant so
// per-request GetBool lookups never hit the DB. Goes through WithAdminAudit
// against the BYPASSRLS admin pool: WithTenant would scope to one tenant,
// and no GUC at all returns zero rows once RLS is enabled. The
// audit log entry on entry surfaces every cache refresh; today that is
// once per process start, but a future hot-reload feature would surface
// each call.
// in: none. out: error.
func (s *SettingsService) Refresh() error {
	ctx := context.Background()
	fresh := make(map[string]json.RawMessage, 8)
	err := db.WithAdminAudit(ctx, s.pools.Admin, "settings.cache_refresh",
		func(tx pgx.Tx) error {
			rows, err := tx.Query(ctx, `SELECT tenant_id, key, value FROM settings`)
			if err != nil {
				return err
			}
			defer rows.Close()
			for rows.Next() {
				var tenantID, key string
				var value json.RawMessage
				if err := rows.Scan(&tenantID, &key, &value); err != nil {
					return err
				}
				fresh[settingsCacheKey(tenantID, key)] = value
			}
			return rows.Err()
		})
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.cache = fresh
	s.mu.Unlock()
	return nil
}

// GetBool returns a cached boolean setting, or fallback if unset / parse fail.
// in: tenant_id, key, fallback default. out: bool.
func (s *SettingsService) GetBool(tenantID, key string, fallback bool) bool {
	s.mu.RLock()
	raw, ok := s.cache[settingsCacheKey(tenantID, key)]
	s.mu.RUnlock()
	if !ok {
		return fallback
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return fallback
	}
	return b
}

// SetBool upserts a boolean setting and refreshes the cache entry.
// Tenant-scoped write through WithTenant so the RLS policy on `settings`
// evaluates app.tenant_id and rejects any caller-side tenantID that does
// not match the GUC. Belt + suspenders: the WHERE clause in the upsert
// still pins tenant_id explicitly so a caller passing the wrong ID is
// caught at the policy layer rather than corrupting another tenant's
// row. ErrNoTenant if tenantID is empty.
// in: tenant_id, key, value. out: error.
func (s *SettingsService) SetBool(tenantID, key string, value bool) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	ctx := context.Background()
	err = db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, execErr := tx.Exec(ctx,
			`INSERT INTO settings (tenant_id, key, value) VALUES ($1, $2, $3)
			 ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()`,
			tenantID, key, raw)
		return execErr
	})
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.cache == nil {
		s.cache = make(map[string]json.RawMessage)
	}
	s.cache[settingsCacheKey(tenantID, key)] = raw
	s.mu.Unlock()
	return nil
}
