-- no-transaction
-- WHY: the ingest check looks up a rule's open trend alert per reading. CONCURRENTLY cannot run in a transaction.
-- Rollback: DROP INDEX CONCURRENTLY IF EXISTS device_alerts_open_trend_idx;

CREATE INDEX CONCURRENTLY IF NOT EXISTS device_alerts_open_trend_idx
    ON device_alerts (device_pk, (raw->>'rule'))
    WHERE code LIKE 'trend.%' AND cleared_at IS NULL;
