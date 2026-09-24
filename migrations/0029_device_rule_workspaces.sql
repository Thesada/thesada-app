-- Blockly visual-rules workspaces (#38).
--
-- device_files already stores the Lua the device runs (/scripts/rules.lua).
-- This pair of tables stores the Blockly workspace that authored it so the
-- editor can round-trip. Workspace JSON is authoritative for editing; lua_*
-- is the generated artifact (also pushed via the existing file-write path).
--
-- Slots start as rules.lua and main.lua. New slots are a follow-up; the
-- CHECK keeps the vocabulary closed until then.
--
-- Created after the ALL-TABLES grant in 0001_init, so both tables need
-- explicit grants below (same pattern as 0023).

CREATE TABLE device_rule_workspaces (
    device_pk      UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    slot           TEXT NOT NULL,
    workspace_json TEXT NOT NULL,
    lua_content    TEXT NOT NULL,
    lua_sha256     TEXT NOT NULL,
    source         TEXT NOT NULL DEFAULT 'editor',
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_by     UUID REFERENCES users(id),
    PRIMARY KEY (device_pk, slot),
    CONSTRAINT device_rule_workspaces_slot_check
        CHECK (slot IN ('rules.lua', 'main.lua'))
);

-- Immutable save history. tenant_id is denormalized so the RLS policy stays
-- single-hop (same pattern as device_file_history).
CREATE TABLE device_rule_workspace_history (
    id             BIGSERIAL PRIMARY KEY,
    device_pk      UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    slot           TEXT NOT NULL,
    workspace_json TEXT NOT NULL,
    lua_content    TEXT NOT NULL,
    lua_sha256     TEXT NOT NULL,
    prev_sha256    TEXT,
    source         TEXT NOT NULL,
    created_by     UUID REFERENCES users(id),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    tenant_id      TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    CONSTRAINT device_rule_workspace_history_slot_check
        CHECK (slot IN ('rules.lua', 'main.lua'))
);
CREATE INDEX idx_drwh_device_slot_created
    ON device_rule_workspace_history (device_pk, slot, created_at DESC);
CREATE INDEX idx_drwh_tenant_slot_created
    ON device_rule_workspace_history (tenant_id, slot, created_at DESC);

CREATE OR REPLACE FUNCTION device_rule_workspace_history_set_tenant() RETURNS TRIGGER AS $$
BEGIN
    SELECT tenant_id INTO NEW.tenant_id
      FROM devices
     WHERE id = NEW.device_pk;
    IF NEW.tenant_id IS NULL THEN
        RAISE EXCEPTION 'device_rule_workspace_history insert: device_pk % has no matching devices row', NEW.device_pk;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_device_rule_workspace_history_set_tenant
    BEFORE INSERT ON device_rule_workspace_history
    FOR EACH ROW EXECUTE FUNCTION device_rule_workspace_history_set_tenant();

GRANT SELECT, INSERT, UPDATE, DELETE ON device_rule_workspaces
    TO thesada_app, thesada_app_admin;
-- History is append-only; deny UPDATE/DELETE so app roles cannot rewrite past saves.
GRANT SELECT, INSERT ON device_rule_workspace_history
    TO thesada_app, thesada_app_admin;
GRANT USAGE, SELECT ON SEQUENCE device_rule_workspace_history_id_seq
    TO thesada_app, thesada_app_admin;

ALTER TABLE device_rule_workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_rule_workspaces FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_device_rule_workspaces_tenant ON device_rule_workspaces
    USING (EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = device_rule_workspaces.device_pk
          AND d.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM devices d
        WHERE d.id = device_rule_workspaces.device_pk
          AND d.tenant_id = app_tenant_id()));

ALTER TABLE device_rule_workspace_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE device_rule_workspace_history FORCE  ROW LEVEL SECURITY;
CREATE POLICY p_device_rule_workspace_history_tenant ON device_rule_workspace_history
    USING (tenant_id = app_tenant_id())
    WITH CHECK (tenant_id = app_tenant_id());
