-- 0024_wifi_per_ssid_secrets.sql
--
-- WHY: the firmware stores one WiFi password per network in wifi.networks[],
-- each provisioned into NVS under a per-SSID key (secret.set
-- wifi.password:<ssid>). The app could store only a single bare "wifi.password"
-- (0023 CHECK), so a device with more than one network got exactly one of its
-- passwords into the encrypted store and the rest stayed plaintext in
-- config.json. Relax the field CHECK to also accept "wifi.password:<ssid>" so
-- the app can hold one row per network.
--
-- The bare "wifi.password" value stays valid so existing rows (provisioned
-- against the device's primary SSID at push time) keep working with no data
-- migration; new writes use the per-SSID form. The (device_pk, field) unique
-- index already keys on the full field string, so per-SSID rows coexist.
--
-- Rollback caveat: dropping the new form would orphan any wifi.password:<ssid>
-- rows against the old CHECK; delete them first if reverting.

ALTER TABLE device_config_secrets
    DROP CONSTRAINT device_config_secrets_field_check;

ALTER TABLE device_config_secrets
    ADD CONSTRAINT device_config_secrets_field_check CHECK (
        field IN ('wifi.password', 'mqtt.password', 'telegram.bot_token',
                  'web.password', 'wifi.ap_password')
        OR field ~ '^wifi\.password:.+$'
    );
