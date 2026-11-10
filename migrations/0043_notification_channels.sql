-- 0043_notification_channels: a user's alert destinations become rows.
-- WHY: email went to users.email, telegram to users.telegram_chat_id and a
-- webhook to alert_subscriptions.destination. A channel row holds one target,
-- so a user can have several of a kind and switch one off. A subscription
-- keeps its device and severity filter and points at one channel.
-- users.telegram_chat_id and alert_subscriptions.channel/destination stay for
-- one release, read-only except the mirror the app keeps for a rollback.
-- Needs: GRANT thesada_app_admin TO thesada_app (docs/runbook.md, Migrations).
-- Rollback: DROP TABLE notification_channels CASCADE (drops channel_id too).

-- The old app keeps serving during migrate: fail fast rather than queue it.
SET LOCAL lock_timeout = '5s';

CREATE TABLE notification_channels (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('email', 'telegram', 'webhook')),
    target     TEXT NOT NULL CHECK (target <> ''),
    label      TEXT NOT NULL DEFAULT '',
    enabled    BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, kind, target)
);

ALTER TABLE notification_channels ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification_channels FORCE ROW LEVEL SECURITY;
CREATE POLICY p_notification_channels_tenant ON notification_channels
    USING (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = notification_channels.user_id
          AND u.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = notification_channels.user_id
          AND u.tenant_id = app_tenant_id()));

-- Explicit for both roles, like 0038: the default privileges in 0001 apply
-- only when thesada_app creates the table, not under a superuser migrator.
GRANT SELECT, INSERT, UPDATE, DELETE ON notification_channels TO thesada_app, thesada_app_admin;

ALTER TABLE alert_subscriptions
    ADD COLUMN channel_id UUID REFERENCES notification_channels(id) ON DELETE CASCADE;
CREATE INDEX alert_subscriptions_channel_idx ON alert_subscriptions (channel_id);

SET LOCAL ROLE thesada_app_admin;

DO $$
BEGIN
    IF NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION '0043 needs a role that bypasses RLS, got %', current_user;
    END IF;
END $$;

-- Every account address, every saved chat id and every webhook URL in use.
INSERT INTO notification_channels (user_id, kind, target)
SELECT id, 'email', email::text FROM users
UNION
SELECT id, 'telegram', btrim(telegram_chat_id) FROM users
 WHERE btrim(coalesce(telegram_chat_id, '')) <> ''
UNION
SELECT user_id, 'webhook', destination FROM alert_subscriptions
 WHERE channel = 'webhook' AND coalesce(destination, '') <> ''
ON CONFLICT (user_id, kind, target) DO NOTHING;

-- A telegram subscription without a chat id stays unlinked, it never sent.
UPDATE alert_subscriptions s
   SET channel_id = c.id
  FROM notification_channels c, users u
 WHERE u.id = s.user_id
   AND c.user_id = s.user_id
   AND c.kind = s.channel
   AND c.target = CASE s.channel
                      WHEN 'email'    THEN u.email::text
                      WHEN 'telegram' THEN btrim(u.telegram_chat_id)
                      ELSE s.destination
                  END
   AND s.channel_id IS NULL;

RESET ROLE;
