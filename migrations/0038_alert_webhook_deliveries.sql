-- WHY: a retry must POST only the webhook subscriptions that failed.
-- Rollback: DROP TABLE alert_webhook_deliveries;

CREATE TABLE alert_webhook_deliveries (
    alert_id        BIGINT NOT NULL REFERENCES device_alerts(id) ON DELETE CASCADE,
    subscription_id UUID NOT NULL REFERENCES alert_subscriptions(id) ON DELETE CASCADE,
    PRIMARY KEY (alert_id, subscription_id)
);

ALTER TABLE alert_webhook_deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_webhook_deliveries FORCE ROW LEVEL SECURITY;
CREATE POLICY p_alert_webhook_deliveries_tenant ON alert_webhook_deliveries
    USING (EXISTS (
        SELECT 1 FROM device_alerts a
        JOIN devices d ON d.id = a.device_pk
        WHERE a.id = alert_webhook_deliveries.alert_id
          AND d.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM device_alerts a
        JOIN devices d ON d.id = a.device_pk
        WHERE a.id = alert_webhook_deliveries.alert_id
          AND d.tenant_id = app_tenant_id()));

GRANT SELECT, INSERT ON alert_webhook_deliveries TO thesada_app, thesada_app_admin;
