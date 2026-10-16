-- WHY: a tenant reuses one Blockly workspace on many devices. The hash is
-- how the rules page spots drift from the copy saved on a device.
-- Rollback: DROP TABLE rule_templates. No other table references it.

CREATE TABLE rule_templates (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name       TEXT NOT NULL,
    lua_sha256 TEXT NOT NULL,
    workspace  TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, name)
);

ALTER TABLE rule_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_templates FORCE ROW LEVEL SECURITY;
CREATE POLICY p_rule_templates_tenant ON rule_templates
    USING (tenant_id = app_tenant_id())
    WITH CHECK (tenant_id = app_tenant_id());

GRANT SELECT, INSERT, UPDATE, DELETE ON rule_templates TO thesada_app, thesada_app_admin;
