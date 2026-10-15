-- WHY: a later delivery attempt must not POST a webhook that already
-- succeeded. Rollback: ALTER TABLE device_alerts DROP COLUMN delivered_webhook.

ALTER TABLE device_alerts
    ADD COLUMN delivered_webhook BOOLEAN NOT NULL DEFAULT false;
