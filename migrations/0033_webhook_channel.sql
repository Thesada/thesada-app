-- WHY: a webhook channel needs a URL. Email and telegram do not, so
-- destination stays null for them. Rollback: drop destination and restore
-- the previous channel check that listed only email and telegram.

ALTER TABLE alert_subscriptions DROP CONSTRAINT alert_subscriptions_channel_check;
ALTER TABLE alert_subscriptions
    ADD CONSTRAINT alert_subscriptions_channel_check
    CHECK (channel IN ('email', 'telegram', 'webhook')) NOT VALID;
ALTER TABLE alert_subscriptions VALIDATE CONSTRAINT alert_subscriptions_channel_check;
ALTER TABLE alert_subscriptions ADD COLUMN destination TEXT;
ALTER TABLE alert_subscriptions
    ADD CONSTRAINT alert_subscriptions_webhook_dest
    CHECK (channel <> 'webhook' OR destination IS NOT NULL) NOT VALID;
ALTER TABLE alert_subscriptions VALIDATE CONSTRAINT alert_subscriptions_webhook_dest;
