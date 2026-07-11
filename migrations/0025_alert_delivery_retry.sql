-- 0025_alert_delivery_retry.sql
--
-- WHY: notification delivery was best-effort - a failed email/Telegram send
-- was logged and abandoned, and a process death between insert and the
-- fire-and-forget dispatch left the alert permanently undelivered. These
-- columns carry the retry/redispatch lifecycle:
--
--   delivery_status   pending | delivered | none (no matching subscription)
--                     | dead (attempt budget spent)
--   delivery_attempts dispatch runs executed for this row
--   next_attempt_at   when the redispatch sweeper may retry (backoff)
--
-- The per-channel delivered_email / delivered_telegram flags stay: they keep
-- a retry from re-sending a channel that already succeeded; delivery_status
-- gives the sweeper one cheap predicate.
--
-- Backfill grandfathers pre-existing rows to 'delivered' / 'none' so the
-- sweeper never mass-redelivers historical alerts on first boot.

ALTER TABLE device_alerts
    ADD COLUMN delivery_status TEXT NOT NULL DEFAULT 'pending'
        CHECK (delivery_status IN ('pending', 'delivered', 'none', 'dead')),
    ADD COLUMN delivery_attempts SMALLINT NOT NULL DEFAULT 0,
    ADD COLUMN next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE device_alerts
SET delivery_status = CASE
        WHEN delivered_email OR delivered_telegram THEN 'delivered'
        ELSE 'none'
    END;

-- Partial index keeps the every-tick "pending and due" scan off the main
-- table path; pending rows are transient so it stays tiny.
CREATE INDEX device_alerts_redispatch_idx
    ON device_alerts (next_attempt_at)
    WHERE delivery_status = 'pending';
