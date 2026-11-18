-- 0048_device_open_networks: open WiFi markers leave the secret store, config staleness moves to the DB.
-- WHY: the store held "" for an open network, so a device read could overwrite a
-- real password with "" and provisioning pushed it as secret.set <field> "", which
-- clears NVS (C1, #99). A marker counts for the write guard only while seen_at is
-- newer than devices.config_changed_at. devices.config_read_at is the start of the
-- newest stored device read, so an older read that answers late is dropped.
-- An AES-GCM blob of "" is 28 bytes (12 nonce + 16 tag), so the move needs no key.
-- Needs: GRANT thesada_app_admin TO thesada_app (docs/runbook.md, Migrations).
-- Rollback: ALTER TABLE device_config_secrets DROP CONSTRAINT device_config_secrets_not_empty;
--           DROP TABLE device_open_networks;
--           ALTER TABLE devices DROP COLUMN config_changed_at, DROP COLUMN config_read_at;
--           The moved markers are not restored: the next device read records them again.

SET LOCAL lock_timeout = '5s';

ALTER TABLE devices
    ADD COLUMN config_changed_at TIMESTAMPTZ,
    ADD COLUMN config_read_at    TIMESTAMPTZ;

CREATE TABLE device_open_networks (
    tenant_id TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_pk UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ssid      TEXT NOT NULL CHECK (ssid <> ''),
    seen_at   TIMESTAMPTZ NOT NULL,
    source    TEXT NOT NULL CHECK (source <> ''),
    PRIMARY KEY (device_pk, ssid)
);

-- Same scoping as device_config_secrets: direct tenant_id, device bound on write.
ALTER TABLE device_open_networks ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_open_networks FORCE ROW LEVEL SECURITY;
CREATE POLICY p_device_open_networks_tenant ON device_open_networks
    USING (tenant_id = app_tenant_id())
    WITH CHECK (
        tenant_id = app_tenant_id()
        AND EXISTS (
            SELECT 1 FROM devices d
             WHERE d.id = device_open_networks.device_pk
               AND d.tenant_id = app_tenant_id()));

-- Explicit for both roles, like 0038 and 0043.
GRANT SELECT, INSERT, UPDATE, DELETE ON device_open_networks TO thesada_app, thesada_app_admin;

SET LOCAL ROLE thesada_app_admin;

DO $$
BEGIN
    IF NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION '0048 needs a role that bypasses RLS, got %', current_user;
    END IF;
END $$;

-- Device rows holding "" for a named network become markers, seen when they were stored.
INSERT INTO device_open_networks (tenant_id, device_pk, ssid, seen_at, source)
SELECT tenant_id, device_pk, substr(field, length('wifi.password:') + 1), updated_at, 'migration'
  FROM device_config_secrets
 WHERE device_pk IS NOT NULL
   AND field LIKE 'wifi.password:_%'
   AND octet_length(ciphertext) = 28
ON CONFLICT (device_pk, ssid) DO NOTHING;

-- No empty value stays a secret, at either level and for any field.
DELETE FROM device_config_secrets WHERE octet_length(ciphertext) = 28;

RESET ROLE;

ALTER TABLE device_config_secrets
    ADD CONSTRAINT device_config_secrets_not_empty CHECK (octet_length(ciphertext) > 28);
