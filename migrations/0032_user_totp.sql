-- WHY: a password or magic-link login must not open a session until the
-- second factor is checked. A null secret means the factor is off.
-- totp_challenges is the 5 minute gap and remembers which method resumes.
-- Rollback: DROP TABLE totp_challenges; ALTER TABLE users DROP COLUMN totp_secret.

ALTER TABLE users ADD COLUMN totp_secret TEXT;

CREATE TABLE totp_challenges (
    token_hash BYTEA PRIMARY KEY,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    method     TEXT NOT NULL,
    attempts   INT NOT NULL DEFAULT 0
);

ALTER TABLE totp_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE totp_challenges FORCE ROW LEVEL SECURITY;
CREATE POLICY p_totp_challenges_tenant ON totp_challenges
    USING (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = totp_challenges.user_id
          AND u.tenant_id = app_tenant_id()))
    WITH CHECK (EXISTS (
        SELECT 1 FROM users u
        WHERE u.id = totp_challenges.user_id
          AND u.tenant_id = app_tenant_id()));

-- Created after the blanket grant in 0001. The finish path reads this
-- table as thesada_app_admin. The begin path writes it as thesada_app.
GRANT SELECT, INSERT, DELETE ON totp_challenges TO thesada_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON totp_challenges TO thesada_app_admin;
