-- 0042_user_passkeys: WebAuthn passkeys as a second factor next to TOTP.
-- WHY: a security key or phone passkey replaces the 6 digit code at the same
-- point of a password or magic-link login. The password stays the first factor.
-- passkey_ceremonies holds the server side of one register or login ceremony.
-- Rollback: DROP TABLE passkey_ceremonies; DROP TABLE user_passkeys;

CREATE TABLE user_passkeys (
    id               BIGSERIAL PRIMARY KEY,
    user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id    BYTEA NOT NULL UNIQUE,
    public_key       BYTEA NOT NULL,
    attestation_type TEXT NOT NULL DEFAULT '',
    aaguid           BYTEA,
    sign_count       BIGINT NOT NULL DEFAULT 0,
    transports       TEXT[] NOT NULL DEFAULT '{}',
    backup_eligible  BOOLEAN NOT NULL DEFAULT false,
    backup_state     BOOLEAN NOT NULL DEFAULT false,
    name             TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at     TIMESTAMPTZ
);
CREATE INDEX user_passkeys_user_idx ON user_passkeys (user_id);

ALTER TABLE user_passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_passkeys FORCE ROW LEVEL SECURITY;
CREATE POLICY p_user_passkeys_tenant ON user_passkeys
    USING (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = user_passkeys.user_id
          AND u.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = user_passkeys.user_id
          AND u.tenant_id = app_tenant_id()));

CREATE TABLE passkey_ceremonies (
    token_hash BYTEA PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind       TEXT NOT NULL CHECK (kind IN ('register', 'login')),
    session    JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

ALTER TABLE passkey_ceremonies ENABLE ROW LEVEL SECURITY;
ALTER TABLE passkey_ceremonies FORCE ROW LEVEL SECURITY;
CREATE POLICY p_passkey_ceremonies_tenant ON passkey_ceremonies
    USING (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = passkey_ceremonies.user_id
          AND u.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = passkey_ceremonies.user_id
          AND u.tenant_id = app_tenant_id()));

-- Created after the blanket grant in 0001. Settings run as thesada_app.
-- The login finish path reads both as thesada_app_admin, like totp_challenges.
GRANT SELECT, INSERT, UPDATE, DELETE ON user_passkeys TO thesada_app;
GRANT USAGE, SELECT ON SEQUENCE user_passkeys_id_seq TO thesada_app;
GRANT SELECT, INSERT, DELETE ON passkey_ceremonies TO thesada_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON user_passkeys TO thesada_app_admin;
GRANT USAGE, SELECT ON SEQUENCE user_passkeys_id_seq TO thesada_app_admin;
GRANT SELECT, INSERT, UPDATE, DELETE ON passkey_ceremonies TO thesada_app_admin;
