-- 0049_secret_rekeyed: marks a device secret row written by the legacy WiFi re-key.
-- WHY: a WiFi clear drops a per-SSID row that appeared during it only when that row is
-- the bare legacy row re-keyed. Every other write clears the flag, so a save of the same
-- password is told apart by its write, not by its value. Rows before 0049 read false.
-- A constant default adds the column without a table rewrite. No data step.
-- Rollback: ALTER TABLE device_config_secrets DROP COLUMN rekeyed;

SET LOCAL lock_timeout = '5s';

ALTER TABLE device_config_secrets
    ADD COLUMN rekeyed BOOLEAN NOT NULL DEFAULT false;
