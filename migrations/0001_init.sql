-- thesada-app initial schema (v1 consolidated).
--
-- Squash of the historical 0001-0021 migrations into one init for fresh
-- installs. Produces the exact post-0021 schema: dropped tables/columns are
-- omitted, data backfills dropped (no-ops on an empty DB), and post-create
-- ALTERs folded into their CREATE (columns appended in historical order to
-- match a sequentially-migrated DB).
--
-- Prod safety: production already records "0001_init" in schema_migrations
-- (bootstrap-seeded), so this file is skipped there; only fresh installs run
-- it. 0022_api_tokens.sql stays a separate file - renumbering it would change
-- its version key and re-run it on prod.
--
-- The runner executes this whole file in one transaction (runOne) and strips
-- any outer BEGIN/COMMIT, so the TimescaleDB hypertable + continuous
-- aggregates are created the same way migration 0003 created them.
--
-- thesada_app (role) and the thesada_app database are provisioned out of band
-- (deploy automation / dev harness) before migrations run.
-- Multi-tenant from day 1, single tenant ('default') in practice for v1.

CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS citext;

-- Tenants -------------------------------------------------------------------
-- id doubles as the URL slug + MQTT topic prefix; immutable by trigger.
CREATE TABLE tenants (
    id           TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    uuid         UUID NOT NULL UNIQUE DEFAULT gen_random_uuid(),
    CONSTRAINT tenants_id_slug_format CHECK (id ~ '^[a-z0-9-]{3,32}$'),
    CONSTRAINT tenants_id_reserved CHECK (id NOT IN (
        'admin', 'system', 'api', 'provision', 'status',
        'info', 'sensor', 'alert', 'cli', 'cmd', 'homeassistant'
    ))
);

CREATE OR REPLACE FUNCTION tenants_slug_immutable() RETURNS trigger AS $$
BEGIN
    IF NEW.id IS DISTINCT FROM OLD.id THEN
        RAISE EXCEPTION 'tenants.id (slug) is immutable';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER tenants_slug_immutable_trigger
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION tenants_slug_immutable();

INSERT INTO tenants (id, display_name) VALUES ('default', 'Default Tenant');

-- Settings (key/value, scoped per tenant) -----------------------------------
CREATE TABLE settings (
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key        TEXT NOT NULL,
    value      JSONB NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key)
);

INSERT INTO settings (tenant_id, key, value) VALUES
    ('default', 'invite_only_mode', 'true'::jsonb),
    ('default', 'multi_tenant_mode', 'false'::jsonb);

-- Users ---------------------------------------------------------------------
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email           CITEXT NOT NULL,
    password_hash   TEXT,
    display_name    TEXT,
    telegram_chat_id TEXT,
    is_admin        BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ,
    is_super_admin  BOOLEAN NOT NULL DEFAULT false
);
CREATE UNIQUE INDEX users_tenant_email_idx ON users (tenant_id, email);

-- Sessions ------------------------------------------------------------------
-- Cookie value is the session token (random 32 bytes, base64url).
CREATE TABLE user_sessions (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash  BYTEA NOT NULL UNIQUE,
    auth_method TEXT NOT NULL CHECK (auth_method IN ('password','magic_link','oidc')),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ NOT NULL,
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    user_agent  TEXT,
    ip          INET,
    impersonated_tenant_id TEXT REFERENCES tenants(id) ON DELETE SET NULL,
    rotated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    previous_token_hash BYTEA,
    previous_token_hash_expires_at TIMESTAMPTZ
);
CREATE INDEX user_sessions_user_idx ON user_sessions (user_id);
CREATE INDEX user_sessions_expiry_idx ON user_sessions (expires_at);
CREATE INDEX user_sessions_previous_token_hash_idx
    ON user_sessions (previous_token_hash)
    WHERE previous_token_hash IS NOT NULL;

-- Magic link tokens (short-lived, single-use) -------------------------------
CREATE TABLE magic_link_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL UNIQUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    purpose    TEXT NOT NULL DEFAULT 'login' CHECK (purpose IN ('login', 'reset'))
);

-- Waitlist (used when settings.invite_only_mode = true) ---------------------
CREATE TABLE waitlist (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email      CITEXT NOT NULL,
    note       TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    converted_user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE (tenant_id, email)
);

-- Devices -------------------------------------------------------------------
CREATE TABLE devices (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    owner_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    device_id       TEXT NOT NULL,           -- factory-assigned, on the label
    pairing_key     TEXT,                    -- random short string, factory
    paired_at       TIMESTAMPTZ,
    display_name    TEXT,
    hardware_type   TEXT,                    -- e.g. 'owb-monitor', 'sht31'
    firmware_version TEXT,
    last_seen_at    TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    mqtt_topic_prefix TEXT,
    UNIQUE (tenant_id, device_id)
);
CREATE INDEX devices_owner_idx ON devices (owner_user_id);

-- Telemetry (sensor readings) -----------------------------------------------
-- TimescaleDB hypertable: 1-day chunks, raw retained 90 days, compression on
-- chunks older than 7 days, hourly + daily continuous-aggregate rollups.
CREATE TABLE device_telemetry (
    id          BIGSERIAL,
    device_pk   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    metric      TEXT NOT NULL,    -- e.g. 'temp.boiler', 'voltage.battery'
    value_num   DOUBLE PRECISION,
    value_text  TEXT,
    raw         JSONB,
    PRIMARY KEY (id, received_at)
);
CREATE INDEX device_telemetry_device_metric_time_idx
    ON device_telemetry (device_pk, metric, received_at DESC);

SELECT create_hypertable(
    'device_telemetry',
    'received_at',
    chunk_time_interval => INTERVAL '1 day',
    if_not_exists => TRUE,
    migrate_data => TRUE
);

ALTER TABLE device_telemetry SET (
    timescaledb.compress,
    timescaledb.compress_segmentby = 'device_pk, metric',
    timescaledb.compress_orderby = 'received_at DESC'
);

DO $$
BEGIN
    PERFORM add_compression_policy('device_telemetry', INTERVAL '7 days');
EXCEPTION WHEN duplicate_object THEN
    NULL;
END $$;

DO $$
BEGIN
    PERFORM add_retention_policy('device_telemetry', INTERVAL '90 days');
EXCEPTION WHEN duplicate_object THEN
    NULL;
END $$;

-- Hourly rollup (numeric metrics only).
CREATE MATERIALIZED VIEW IF NOT EXISTS device_telemetry_hourly
WITH (timescaledb.continuous) AS
SELECT
    device_pk,
    metric,
    time_bucket(INTERVAL '1 hour', received_at) AS bucket,
    AVG(value_num)   AS avg_val,
    MIN(value_num)   AS min_val,
    MAX(value_num)   AS max_val,
    COUNT(*)         AS count
FROM device_telemetry
WHERE value_num IS NOT NULL
GROUP BY device_pk, metric, bucket
WITH NO DATA;

DO $$
BEGIN
    PERFORM add_continuous_aggregate_policy(
        'device_telemetry_hourly',
        start_offset => INTERVAL '1 week',
        end_offset => INTERVAL '1 hour',
        schedule_interval => INTERVAL '1 hour'
    );
EXCEPTION WHEN duplicate_object THEN
    NULL;
END $$;

-- Daily rollup.
CREATE MATERIALIZED VIEW IF NOT EXISTS device_telemetry_daily
WITH (timescaledb.continuous) AS
SELECT
    device_pk,
    metric,
    time_bucket(INTERVAL '1 day', received_at) AS bucket,
    AVG(value_num)   AS avg_val,
    MIN(value_num)   AS min_val,
    MAX(value_num)   AS max_val,
    COUNT(*)         AS count
FROM device_telemetry
WHERE value_num IS NOT NULL
GROUP BY device_pk, metric, bucket
WITH NO DATA;

DO $$
BEGIN
    PERFORM add_continuous_aggregate_policy(
        'device_telemetry_daily',
        start_offset => INTERVAL '1 month',
        end_offset => INTERVAL '1 day',
        schedule_interval => INTERVAL '1 day'
    );
EXCEPTION WHEN duplicate_object THEN
    NULL;
END $$;

-- Alerts (events emitted by devices) ----------------------------------------
CREATE TABLE device_alerts (
    id          BIGSERIAL PRIMARY KEY,
    device_pk   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    received_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    severity    TEXT NOT NULL CHECK (severity IN ('info','warn','crit')),
    code        TEXT,
    message     TEXT NOT NULL,
    raw         JSONB,
    delivered_email    BOOLEAN NOT NULL DEFAULT false,
    delivered_telegram BOOLEAN NOT NULL DEFAULT false
);
CREATE INDEX device_alerts_device_time_idx ON device_alerts (device_pk, received_at DESC);

-- Alert subscriptions -------------------------------------------------------
CREATE TABLE alert_subscriptions (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_pk  UUID REFERENCES devices(id) ON DELETE CASCADE,  -- NULL = all devices
    channel    TEXT NOT NULL CHECK (channel IN ('email','telegram')),
    min_severity TEXT NOT NULL DEFAULT 'warn'
        CHECK (min_severity IN ('info','warn','crit')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX alert_subscriptions_device_idx ON alert_subscriptions (device_pk);

-- Device certificates (mTLS client certs) -----------------------------------
CREATE TABLE device_certificates (
  id           BIGSERIAL PRIMARY KEY,
  device_pk    UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  serial_hex   TEXT NOT NULL UNIQUE,
  cn           TEXT NOT NULL,
  not_before   TIMESTAMPTZ NOT NULL,
  not_after    TIMESTAMPTZ NOT NULL,
  cert_pem     TEXT NOT NULL,
  revoked      BOOLEAN NOT NULL DEFAULT false,
  revoked_at   TIMESTAMPTZ,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_dc_device ON device_certificates (device_pk);

-- OAuth / OIDC --------------------------------------------------------------
-- Providers are per-tenant. tenant_id stays nullable for the COALESCE-based
-- unique index, but RLS treats NULL as "no tenant"; tenant-create seeds rows.
CREATE TABLE oauth_providers (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    slug            TEXT NOT NULL,
    display_name    TEXT NOT NULL,
    kind            TEXT NOT NULL DEFAULT 'oidc'
                        CHECK (kind IN ('oidc','oauth2')),
    issuer_url      TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    client_secret   TEXT NOT NULL DEFAULT '',
    scopes          TEXT[] NOT NULL DEFAULT ARRAY['openid','profile','email'],
    enabled         BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX oauth_providers_slug_uniq
    ON oauth_providers (COALESCE(tenant_id, ''), slug);

CREATE TABLE user_oauth_identities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider_id     UUID NOT NULL REFERENCES oauth_providers(id) ON DELETE CASCADE,
    subject         TEXT NOT NULL,
    email           CITEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_login_at   TIMESTAMPTZ,
    UNIQUE (provider_id, subject)
);
CREATE INDEX user_oauth_identities_user_idx
    ON user_oauth_identities (user_id);

CREATE TABLE oauth_auth_requests (
    state           TEXT PRIMARY KEY,
    provider_id     UUID NOT NULL REFERENCES oauth_providers(id) ON DELETE CASCADE,
    nonce           TEXT NOT NULL,
    pkce_verifier   TEXT NOT NULL,
    return_to       TEXT NOT NULL DEFAULT '/',
    linking_user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at      TIMESTAMPTZ NOT NULL
);
CREATE INDEX oauth_auth_requests_expires_idx
    ON oauth_auth_requests (expires_at);

-- Seed the platform IdP (Kanidm) scoped to the default tenant. Disabled +
-- empty secret until deploy stamps the real client_secret.
INSERT INTO oauth_providers (tenant_id, slug, display_name, kind, issuer_url, client_id, scopes, enabled)
VALUES (
    'default',
    'kanidm',
    'Thesada SSO',
    'oidc',
    'https://auth.example.com/oauth2/openid/thesada-app',
    'thesada-app',
    ARRAY['openid','profile','email','groups'],
    false
)
ON CONFLICT DO NOTHING;

-- Device files (canonical state + immutable history + drift observations) ----
CREATE TABLE device_files (
  device_pk  UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  path       TEXT NOT NULL,
  content    TEXT NOT NULL,
  sha256     TEXT NOT NULL,
  source     TEXT NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_by UUID REFERENCES users(id),
  PRIMARY KEY (device_pk, path)
);

-- tenant_id denormalized onto history so the RLS policy stays single-hop;
-- the INSERT trigger copies it from the parent device (parent wins).
CREATE TABLE device_file_history (
  id          BIGSERIAL PRIMARY KEY,
  device_pk   UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  path        TEXT NOT NULL,
  content     TEXT NOT NULL,
  sha256      TEXT NOT NULL,
  prev_sha256 TEXT,
  source      TEXT NOT NULL,
  created_by  UUID REFERENCES users(id),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE
);
CREATE INDEX idx_dfh_device_path_created
  ON device_file_history (device_pk, path, created_at DESC);
CREATE INDEX idx_dfh_tenant_path_created
  ON device_file_history (tenant_id, path, created_at DESC);

CREATE OR REPLACE FUNCTION device_file_history_set_tenant() RETURNS TRIGGER AS $$
BEGIN
    SELECT tenant_id INTO NEW.tenant_id
      FROM devices
     WHERE id = NEW.device_pk;
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'device_file_history insert: device_pk % has no matching devices row', NEW.device_pk;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_device_file_history_set_tenant
    BEFORE INSERT ON device_file_history
    FOR EACH ROW EXECUTE FUNCTION device_file_history_set_tenant();

CREATE TABLE device_file_observations (
  id              BIGSERIAL PRIMARY KEY,
  device_pk       UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  path            TEXT NOT NULL,
  reported_sha256 TEXT NOT NULL,
  observed_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX idx_dfo_device_path_observed
  ON device_file_observations (device_pk, path, observed_at DESC);

-- Deleted-device tombstones (retained-clear cascade on offline deletes) ------
CREATE TABLE deleted_device_tombstones (
    id              BIGSERIAL PRIMARY KEY,
    tenant_id       TEXT        NOT NULL,
    device_id       TEXT        NOT NULL,
    topic_prefix    TEXT        NOT NULL,
    deleted_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, device_id)
);
CREATE INDEX deleted_device_tombstones_prefix
    ON deleted_device_tombstones (topic_prefix);

-- Roles + grants ------------------------------------------------------------
-- thesada_app_admin: BYPASSRLS, migrations + audited cross-tenant + cagg
-- refresh. thesada_app_mqtt: narrow ingest pool.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'thesada_app_admin') THEN
        CREATE ROLE thesada_app_admin BYPASSRLS NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'thesada_app_mqtt') THEN
        CREATE ROLE thesada_app_mqtt NOBYPASSRLS NOLOGIN;
    END IF;
END $$;

GRANT CONNECT ON DATABASE thesada_app TO thesada_app_admin, thesada_app_mqtt;
GRANT USAGE   ON SCHEMA   public      TO thesada_app_admin, thesada_app_mqtt;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES    IN SCHEMA public TO thesada_app_admin;
GRANT USAGE,  SELECT, UPDATE         ON ALL SEQUENCES IN SCHEMA public TO thesada_app_admin;

ALTER DEFAULT PRIVILEGES FOR ROLE thesada_app IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO thesada_app_admin;
ALTER DEFAULT PRIVILEGES FOR ROLE thesada_app IN SCHEMA public
    GRANT USAGE, SELECT, UPDATE          ON SEQUENCES TO thesada_app_admin;

-- MQTT role: explicit, narrow, so accidental new-table writes fail loudly.
GRANT INSERT ON device_telemetry, device_alerts TO thesada_app_mqtt;
GRANT SELECT ON devices, device_certificates    TO thesada_app_mqtt;
GRANT USAGE  ON ALL SEQUENCES IN SCHEMA public  TO thesada_app_mqtt;

-- Continuous aggregates: own via thesada_app_admin (audited bypass-RLS role
-- runs the refresh policy), regrant SELECT to the runtime app role.
ALTER MATERIALIZED VIEW device_telemetry_hourly OWNER TO thesada_app_admin;
ALTER MATERIALIZED VIEW device_telemetry_daily  OWNER TO thesada_app_admin;
GRANT SELECT ON device_telemetry_hourly TO thesada_app;
GRANT SELECT ON device_telemetry_daily  TO thesada_app;

-- thesada_app_admin needs LOGIN so the TimescaleDB cagg-refresh background
-- worker can SET ROLE to it. No password set; pg_hba still blocks client auth.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_roles
         WHERE rolname = 'thesada_app_admin' AND rolcanlogin
    ) THEN
        BEGIN
            ALTER ROLE thesada_app_admin LOGIN;
        EXCEPTION WHEN insufficient_privilege THEN
            RAISE WARNING
                'Cannot ALTER ROLE thesada_app_admin from deploy user. '
                'Run as postgres superuser one time: '
                'ALTER ROLE thesada_app_admin LOGIN; '
                'Until then TimescaleDB cagg refresh is broken.';
        END;
    END IF;
END$$;

-- Row-level security --------------------------------------------------------
-- app_tenant_id() reads the app.tenant_id GUC (NULL if unset). Every policy
-- table uses FORCE so the owner role (thesada_app) is gated too; the escape
-- hatch is thesada_app_admin (BYPASSRLS) via db.WithAdminAudit.
CREATE OR REPLACE FUNCTION app_tenant_id() RETURNS TEXT
LANGUAGE sql STABLE PARALLEL SAFE AS $$
    SELECT current_setting('app.tenant_id', true)
$$;

-- DIRECT: tenant_id column on the table.
ALTER TABLE settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE settings FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_settings_tenant ON settings
    USING       (tenant_id = app_tenant_id())
    WITH CHECK  (tenant_id = app_tenant_id());

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_users_tenant ON users
    USING       (tenant_id = app_tenant_id())
    WITH CHECK  (tenant_id = app_tenant_id());

ALTER TABLE waitlist ENABLE ROW LEVEL SECURITY;
ALTER TABLE waitlist FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_waitlist_tenant ON waitlist
    USING       (tenant_id = app_tenant_id())
    WITH CHECK  (tenant_id = app_tenant_id());

ALTER TABLE devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE devices FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_devices_tenant ON devices
    USING       (tenant_id = app_tenant_id())
    WITH CHECK  (tenant_id = app_tenant_id());

ALTER TABLE oauth_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_providers FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_oauth_providers_tenant ON oauth_providers
    USING       (tenant_id = app_tenant_id())
    WITH CHECK  (tenant_id = app_tenant_id());

ALTER TABLE deleted_device_tombstones ENABLE ROW LEVEL SECURITY;
ALTER TABLE deleted_device_tombstones FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_deleted_device_tombstones_tenant ON deleted_device_tombstones
    USING       (tenant_id = app_tenant_id())
    WITH CHECK  (tenant_id = app_tenant_id());

-- DENORMALIZED: tenant_id copied onto the row by the INSERT trigger.
ALTER TABLE device_file_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_file_history FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_device_file_history_tenant ON device_file_history
    USING       (tenant_id = app_tenant_id())
    WITH CHECK  (tenant_id = app_tenant_id());

-- TRANSITIVE via devices.id (device_pk).
-- device_telemetry + caggs: deliberately NO RLS (compressed hypertable /
-- materialized views); reads are tenant-bound via the device_pk lookup.
ALTER TABLE device_alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_alerts FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_device_alerts_tenant ON device_alerts
    USING (EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = device_alerts.device_pk
          AND d.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = device_alerts.device_pk
          AND d.tenant_id = app_tenant_id()));

ALTER TABLE device_certificates ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_certificates FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_device_certificates_tenant ON device_certificates
    USING (EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = device_certificates.device_pk
          AND d.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = device_certificates.device_pk
          AND d.tenant_id = app_tenant_id()));

ALTER TABLE device_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_files FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_device_files_tenant ON device_files
    USING (EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = device_files.device_pk
          AND d.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = device_files.device_pk
          AND d.tenant_id = app_tenant_id()));

ALTER TABLE device_file_observations ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_file_observations FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_device_file_observations_tenant ON device_file_observations
    USING (EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = device_file_observations.device_pk
          AND d.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = device_file_observations.device_pk
          AND d.tenant_id = app_tenant_id()));

-- alert_subscriptions: device_pk is nullable; scope walks user_id -> users.
ALTER TABLE alert_subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_subscriptions FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_alert_subscriptions_tenant ON alert_subscriptions
    USING (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = alert_subscriptions.user_id
          AND u.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = alert_subscriptions.user_id
          AND u.tenant_id = app_tenant_id()));

-- TRANSITIVE via users.id (user_id).
ALTER TABLE user_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_sessions FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_user_sessions_tenant ON user_sessions
    USING (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = user_sessions.user_id
          AND u.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = user_sessions.user_id
          AND u.tenant_id = app_tenant_id()));

ALTER TABLE magic_link_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE magic_link_tokens FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_magic_link_tokens_tenant ON magic_link_tokens
    USING (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = magic_link_tokens.user_id
          AND u.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = magic_link_tokens.user_id
          AND u.tenant_id = app_tenant_id()));

ALTER TABLE user_oauth_identities ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_oauth_identities FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_user_oauth_identities_tenant ON user_oauth_identities
    USING (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = user_oauth_identities.user_id
          AND u.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = user_oauth_identities.user_id
          AND u.tenant_id = app_tenant_id()));

-- TRANSITIVE via oauth_providers.id (provider_id).
ALTER TABLE oauth_auth_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_auth_requests FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_oauth_auth_requests_tenant ON oauth_auth_requests
    USING (EXISTS (
        SELECT 1 FROM oauth_providers op
        WHERE op.id = oauth_auth_requests.provider_id
          AND op.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM oauth_providers op
        WHERE op.id = oauth_auth_requests.provider_id
          AND op.tenant_id = app_tenant_id()));

-- API tokens (bearer tokens for the JSON /api/v1 surface) -------------------
-- Mirrors user_sessions: raw token returned once, only the sha256 hash stored.
-- Created after the ALL-TABLES grant above, so it needs explicit grants.
CREATE TABLE api_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash   BYTEA NOT NULL UNIQUE,
    name         TEXT NOT NULL DEFAULT '',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);
CREATE INDEX api_tokens_user_idx ON api_tokens (user_id);

GRANT SELECT, INSERT, UPDATE, DELETE ON api_tokens TO thesada_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON api_tokens TO thesada_app_admin;

-- TRANSITIVE via users.id (user_id). Validate/Revoke present a raw token with
-- no tenant context, so they run on the admin (BYPASSRLS) pool.
ALTER TABLE api_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_tokens FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_api_tokens_tenant ON api_tokens
    USING (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = api_tokens.user_id
          AND u.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = api_tokens.user_id
          AND u.tenant_id = app_tenant_id()));
