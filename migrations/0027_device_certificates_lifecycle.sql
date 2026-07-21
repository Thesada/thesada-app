-- 0027_device_certificates_lifecycle.sql
--
-- WHY: cert issuance was push-first/persist-last - the pair flow signed a
-- cert, pushed it to the device over MQTT, provisioned dynsec, and only
-- then INSERTed the device_certificates row. A crash or error between the
-- push and the persist left a certed device the DB did not know about.
-- This column carries the issue lifecycle (mirroring the alert
-- delivery_status pattern from 0025):
--
--   pending  row persisted, MQTT push not yet confirmed
--   active   push confirmed (or cert handed to the caller directly, as on
--            the JSON API pair path) - the one live state
--   failed   push failed after persist; superseded by the next Issue
--
-- The flow becomes persist-first: INSERT status='pending' -> push -> flip
-- 'active' on success / 'failed' on error. Readers that mean "live cert"
-- filter on revoked = false AND status = 'active'.
--
-- DEFAULT 'active' grandfathers every existing row: anything issued before
-- this migration was persisted only after a successful push, so 'active'
-- is the truthful backfill and live-cert readers keep matching them.

ALTER TABLE device_certificates
    ADD COLUMN status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('pending', 'active', 'failed'));

-- Partial index keeps the supersede / stuck-pending scans off the main
-- table path; pending rows are transient so it stays tiny.
CREATE INDEX device_certificates_pending_idx
    ON device_certificates (device_pk)
    WHERE status = 'pending';
