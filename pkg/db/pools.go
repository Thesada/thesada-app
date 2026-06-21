// pools.go - the three-pool model for the RLS rollout.
//
// Phase 0 ships this as a struct held by the service layer. Today every
// field can point at the same underlying pool and behavior is unchanged
// from the single-pool world. Phase 1 swaps Admin to a BYPASSRLS-role
// connection string and MQTT to the dedicated ingest pool, and the
// service layer picks the right field per call site without the rest
// of the app having to thread a "which pool" parameter everywhere.
//
// See docs/invariants.md "Tenant isolation" for the full contract.

package db

import "github.com/jackc/pgx/v5/pgxpool"

// Pools bundles the three role-scoped pools the service layer touches.
//
//   - App   : tenant-scoped reads/writes via thesada_app role. Most calls.
//             Wrap each query in db.WithTenant so RLS receives app.tenant_id.
//   - Admin : BYPASSRLS path via thesada_app_admin role. Cross-tenant
//             admin reads. Wrap each call in db.WithAdminAudit so the
//             bypass is logged.
//   - MQTT  : NOBYPASSRLS ingest path via thesada_app_mqtt role. Same RLS
//             gate as App; separate pool so ingest connection budget is
//             isolated from request traffic.
type Pools struct {
	App   *pgxpool.Pool
	Admin *pgxpool.Pool
	MQTT  *pgxpool.Pool
}
