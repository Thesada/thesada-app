-- 0047_channel_email_confirm: an email channel sends only after its address confirms.
-- WHY: any user could point alert mail from the app's sender at any address.
-- A new or changed email target gets a single-use link, only its sha256 is
-- stored. The account's own address counts as confirmed. Telegram and
-- webhook rows leave the columns NULL and are not gated.
-- Existing email channels are marked confirmed: they are live today and the
-- release with this gate is not out yet.
-- Needs: GRANT thesada_app_admin TO thesada_app (docs/runbook.md, Migrations).
-- Rollback: DROP INDEX notification_channels_confirm_idx;
--           ALTER TABLE notification_channels DROP COLUMN confirmed_at,
--             DROP COLUMN confirm_token_hash, DROP COLUMN confirm_expires_at;

SET LOCAL lock_timeout = '5s';

ALTER TABLE notification_channels
    ADD COLUMN confirmed_at       TIMESTAMPTZ,
    ADD COLUMN confirm_token_hash BYTEA,
    ADD COLUMN confirm_expires_at TIMESTAMPTZ;
CREATE UNIQUE INDEX notification_channels_confirm_idx
    ON notification_channels (confirm_token_hash) WHERE confirm_token_hash IS NOT NULL;

SET LOCAL ROLE thesada_app_admin;

DO $$
BEGIN
    IF NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION '0047 needs a role that bypasses RLS, got %', current_user;
    END IF;
END $$;

UPDATE notification_channels
   SET confirmed_at = now()
 WHERE kind = 'email'
   AND confirmed_at IS NULL;

RESET ROLE;
