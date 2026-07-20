-- 0026_admin_audit.sql
--
-- WHY: privileged operator actions (impersonation, waitlist conversion,
-- cert issue/revoke, device delete/reassign, secret set/provision, bulk
-- OTA, MQTT shell publishes) were audited only as slog lines, which live
-- exactly as long as journald retention. This table is the durable,
-- queryable trail: who did what to which object, when, with a small
-- context payload. Values are never stored - detail carries field names,
-- counts, and target labels only.
--
-- Operator-only table, so the RLS treatment inverts the tenant-table
-- pattern: RLS is ENABLEd + FORCEd with NO policy, which is deny-all for
-- every non-BYPASSRLS role. Only thesada_app_admin (BYPASSRLS, reached
-- via db.WithAdminAudit) can read or write rows. tenant_id is a plain
-- TEXT label (no FK) so audit history survives tenant deletion; same
-- reasoning for actor_user_id vs users(id).

CREATE TABLE admin_audit (
    id            BIGSERIAL PRIMARY KEY,
    at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    actor_user_id UUID,                 -- users.id at action time; no FK so rows survive user deletion
    actor_email   TEXT NOT NULL,
    action        TEXT NOT NULL,        -- dotted slug, mirrors pkg/authz Action values ('cert.issue', ...)
    target_type   TEXT,                 -- 'device' | 'tenant' | 'user' | 'waitlist' | ...
    target_id     TEXT,
    tenant_id     TEXT,                 -- tenant slug where applicable; no FK so rows survive tenant deletion
    detail        JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX admin_audit_at_idx        ON admin_audit (at DESC);
CREATE INDEX admin_audit_actor_at_idx  ON admin_audit (actor_user_id, at DESC);
CREATE INDEX admin_audit_action_at_idx ON admin_audit (action, at DESC);

-- 0001's default privileges auto-grant SELECT/INSERT/UPDATE/DELETE on new
-- tables and USAGE/SELECT/UPDATE on new sequences. Revoke EVERYTHING both
-- roles inherited, then grant the narrow append-only set: the trail must
-- not be updatable, deletable, truncatable, or sequence-resettable from
-- any app connection (retention pruning is an operator/superuser job).
REVOKE ALL ON admin_audit               FROM thesada_app, thesada_app_admin;
REVOKE ALL ON SEQUENCE admin_audit_id_seq FROM thesada_app, thesada_app_admin;
GRANT SELECT, INSERT ON admin_audit TO thesada_app_admin;
GRANT USAGE, SELECT ON SEQUENCE admin_audit_id_seq TO thesada_app_admin;

-- Row-level security: no CREATE POLICY on purpose (see header).
ALTER TABLE admin_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_audit FORCE  ROW LEVEL SECURITY;
