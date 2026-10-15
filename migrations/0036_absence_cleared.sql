-- WHY: an absence alert stays open until the device is seen again.
-- cleared_at is that mark. Rollback: ALTER TABLE device_alerts DROP COLUMN cleared_at.

ALTER TABLE device_alerts
    ADD COLUMN cleared_at TIMESTAMPTZ;
