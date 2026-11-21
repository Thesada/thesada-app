-- 0045_trend_rules: server-side trend alert rules (#5).
-- WHY: absence is the only alert the server raises itself. A trend rule fires
-- when a metric moves by at least delta within window_s, checked on ingest.
-- device_pk NULL means every device of the tenant.
-- Rollback: DROP TABLE alert_rules.

SET LOCAL lock_timeout = '5s';

CREATE TABLE alert_rules (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id  TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    device_pk  UUID REFERENCES devices(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL DEFAULT 'trend' CHECK (kind IN ('trend')),
    metric     TEXT NOT NULL CHECK (metric <> ''),
    direction  TEXT NOT NULL CHECK (direction IN ('rise', 'fall', 'either')),
    delta      DOUBLE PRECISION NOT NULL CHECK (delta > 0),
    window_s   INTEGER NOT NULL CHECK (window_s BETWEEN 60 AND 604800),
    severity   TEXT NOT NULL CHECK (severity IN ('info', 'warn', 'crit')),
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX alert_rules_tenant_metric_idx ON alert_rules (tenant_id, metric) WHERE enabled;

ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rules FORCE ROW LEVEL SECURITY;
CREATE POLICY p_alert_rules_tenant ON alert_rules
    USING (tenant_id = app_tenant_id())
    WITH CHECK (tenant_id = app_tenant_id());

-- Explicit for both roles, like 0038 and 0043.
GRANT SELECT, INSERT, UPDATE, DELETE ON alert_rules TO thesada_app, thesada_app_admin;
