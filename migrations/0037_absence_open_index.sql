-- no-transaction
-- WHY: CONCURRENTLY cannot run inside a transaction. Rollback: DROP INDEX CONCURRENTLY IF EXISTS device_alerts_open_absence_idx;

CREATE INDEX CONCURRENTLY IF NOT EXISTS device_alerts_open_absence_idx
    ON device_alerts (device_pk)
    WHERE code = 'absence' AND cleared_at IS NULL;
