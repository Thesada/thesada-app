-- Device-config secrets: envelope-encrypted store for the 5 sensitive
-- config fields (wifi.password, mqtt.password, telegram.bot_token,
-- web.password, wifi.ap_password). Field keys match the firmware secret.set
-- keymap so provisioning maps cleanly.
--
-- Two tables, two key levels (envelope encryption, pkg/secrets):
--   tenant_dek             - per-tenant DEK, wrapped under the deployment
--                            root KEK (THESADA_DEVICE_CONFIG_KEK, never in DB).
--   device_config_secrets  - each secret value, encrypted under its tenant DEK.
--
-- Sealed blobs are nonce||ciphertext in a single BYTEA (pkg/secrets seals
-- and opens the combined form); there is no separate nonce column.
--
-- Created after the ALL-TABLES grant in 0001_init, so - like api_tokens -
-- both tables need explicit grants below.

-- Per-tenant data-encryption key, wrapped under the root KEK.
-- One row per tenant; crypto-shredded when the tenant is deleted (the DEK
-- row cascades away and the tenant's ciphertext becomes unrecoverable).
CREATE TABLE tenant_dek (
    tenant_id    TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    wrapped_dek  BYTEA NOT NULL,                 -- nonce||ciphertext, sealed under root KEK, AAD=tenant_id
    kek_version  INTEGER NOT NULL DEFAULT 1,     -- root-KEK generation, for rotation (phase 7)
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One encrypted secret value per (tenant, device, field). device_pk is
-- NULLABLE so a later feature can add tenant-default secrets; device-level rows
-- are the only ones written in v1.
CREATE TABLE device_config_secrets (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_pk   UUID REFERENCES devices(id) ON DELETE CASCADE,  -- NULL = tenant default (later feature)
    field       TEXT NOT NULL CHECK (field IN (
                    'wifi.password', 'mqtt.password', 'telegram.bot_token',
                    'web.password', 'wifi.ap_password')),
    ciphertext  BYTEA NOT NULL,                  -- nonce||ciphertext under the tenant DEK, AAD=tenant/device/field
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One secret per field per device; a separate partial index for the
-- tenant-default (device_pk NULL) rows since NULLs never collide in a
-- plain unique constraint. Both are the ON CONFLICT targets for upsert.
CREATE UNIQUE INDEX device_config_secrets_device_field
    ON device_config_secrets (device_pk, field) WHERE device_pk IS NOT NULL;
CREATE UNIQUE INDEX device_config_secrets_tenant_field
    ON device_config_secrets (tenant_id, field) WHERE device_pk IS NULL;

-- Grants (both tables live after the 0001 ALL-TABLES grant). The MQTT
-- ingest role never touches secrets.
GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_dek, device_config_secrets
    TO thesada_app, thesada_app_admin;
GRANT USAGE, SELECT ON SEQUENCE device_config_secrets_id_seq
    TO thesada_app, thesada_app_admin;

-- Row-level security ---------------------------------------------------------
-- tenant_dek: DIRECT tenant_id column, same pattern as settings/users.
ALTER TABLE tenant_dek ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_dek FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_tenant_dek_tenant ON tenant_dek
    USING       (tenant_id = app_tenant_id())
    WITH CHECK  (tenant_id = app_tenant_id());

-- device_config_secrets: tenant_id is denormalized on the row (DIRECT read
-- scope), and WITH CHECK additionally binds device_pk to the same tenant so
-- a caller cannot attach another tenant's device_pk to its own row. The AEAD
-- AAD (tenant/device/field) is the second line; this is the first.
ALTER TABLE device_config_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_config_secrets FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_device_config_secrets_tenant ON device_config_secrets
    USING       (tenant_id = app_tenant_id())
    WITH CHECK  (
        tenant_id = app_tenant_id()
        AND (device_pk IS NULL OR EXISTS (
            SELECT 1 FROM devices d
            WHERE d.id = device_config_secrets.device_pk
              AND d.tenant_id = app_tenant_id())));
