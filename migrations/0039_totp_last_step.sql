-- 0039_totp_last_step: remember the last accepted TOTP time step per user.
-- WHY: a code stays valid for three 30 s steps; without this the same code
-- signs in again in a second login inside that window.
-- Rollback: ALTER TABLE users DROP COLUMN totp_last_step;

ALTER TABLE users ADD COLUMN totp_last_step BIGINT;
