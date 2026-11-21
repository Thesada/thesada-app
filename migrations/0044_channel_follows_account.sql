-- 0044_channel_follows_account: the account's own email channel tracks users.email.
-- WHY: 0043 copied the account address into a plain target, so an email change
-- left alerts going to the old address. A follows_account channel takes its
-- target from users.email at send time. One per user. User-added email
-- channels stay plain targets.
-- Needs: GRANT thesada_app_admin TO thesada_app (docs/runbook.md, Migrations).
-- Rollback: DROP INDEX notification_channels_account_idx;
--           ALTER TABLE notification_channels DROP COLUMN follows_account;

SET LOCAL lock_timeout = '5s';

ALTER TABLE notification_channels
    ADD COLUMN follows_account BOOLEAN NOT NULL DEFAULT false,
    ADD CONSTRAINT notification_channels_account_email
        CHECK (NOT follows_account OR kind = 'email');
CREATE UNIQUE INDEX notification_channels_account_idx
    ON notification_channels (user_id) WHERE follows_account;

SET LOCAL ROLE thesada_app_admin;

DO $$
BEGIN
    IF NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION '0044 needs a role that bypasses RLS, got %', current_user;
    END IF;
END $$;

-- The email channel 0043 built from the account address.
UPDATE notification_channels c
   SET follows_account = true
  FROM users u
 WHERE u.id = c.user_id
   AND c.kind = 'email'
   AND c.target = u.email::text
   AND NOT c.follows_account;

RESET ROLE;
