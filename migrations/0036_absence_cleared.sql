-- WHY: an absence alert stays open until the device is seen again.
-- cleared_at is that mark. Rollback: DROP INDEX device_alerts_open_absence_idx; ALTER TABLE device_alerts DROP COLUMN cleared_at.

ALTER TABLE device_alerts
    ADD COLUMN cleared_at TIMESTAMPTZ;

CREATE INDEX device_alerts_open_absence_idx
    ON device_alerts (device_pk)
    WHERE code = 'absence' AND cleared_at IS NULL;
