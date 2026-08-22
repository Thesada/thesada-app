-- 0028_device_enrollments.sql
--
-- WHY: a factory-fresh device has no tenant, no owner and no credential. It
-- cannot be a `devices` row, because devices.tenant_id is NOT NULL REFERENCES
-- tenants(id) and the RLS policy is `tenant_id = app_tenant_id()`. Until a
-- user claims it, the device belongs to nobody, and modelling "nobody" as a
-- holding tenant would mean a user-facing claim endpoint reading through the
-- BYPASSRLS pool - a privileged read in the least privileged place.
--
-- So unclaimed devices live here instead, and graduate into `devices` at
-- claim time. The row holds only what the device already broadcasts on its
-- own label: an id derived from its factory MAC, and the public half of the
-- Ed25519 keypair it minted on first boot. No secrets, no tenant data.
--
-- IDENTITY IS (device_id, pubkey_hex), NOT device_id ALONE. device_id comes
-- from a sequentially assigned factory MAC, so holding one unit tells you the
-- ids of the whole reel: it is a guess, not a credential. Keying rows on
-- device_id alone means the first caller to announce owns the id, and a remote
-- caller who guesses one can pin its own keypair, satisfy the proof with it
-- and lock the real hardware out forever. Keying on the pair instead lets the
-- squatter and the real device each hold their own row; the squatter's row is
-- inert because claiming needs the claim token from the device's own portal
-- QR, and the pubkey - unlike the id - is not derivable from anything
-- broadcast over the air.
--
-- Multiple rows per device_id are therefore expected, not a fault. They are
-- bounded by the per-device_id rate limit on the announce endpoint and are
-- removed by the pruning sweep. There is deliberately NO unique index over
-- device_id for claimed rows: it would re-introduce exactly the lockout above,
-- with an authenticated squatter permanently blocking the real owner's claim.
--
-- NO RLS ON PURPOSE. Every other tenant-bearing table in this schema is
-- ENABLE + FORCE ROW LEVEL SECURITY with a tenant policy; this one has no
-- tenant column to scope by, and adding a nullable tenant_id with an
-- `IS NULL OR ...` carve-out is the exact anti-pattern CODE-GUIDELINES names.
-- Access is confined to the enrollment service, which runs through
-- db.WithAdminAudit so every touch leaves an audit line.
--
-- SECRETS: claim_token is stored hashed, never in plaintext. It is the bearer
-- credential that authorises certificate delivery, so a database read must not
-- yield something replayable. challenge is single-use and short-lived: it is
-- burned before the signature is judged, so a failed attempt spends the nonce
-- too and leaves nothing to grind signatures against.

CREATE TABLE device_enrollments (
    device_id            TEXT NOT NULL,
    pubkey_hex           TEXT NOT NULL,

    -- SHA-256 of the claim token, hex. Never the token itself.
    claim_token_hash     TEXT NOT NULL,

    -- Single-use proof-of-possession nonce. NULL once consumed.
    challenge            TEXT,
    challenge_expires_at TIMESTAMPTZ,

    -- Set when the device returns a valid signature over the challenge.
    verified_at          TIMESTAMPTZ,

    -- Set when an authenticated user claims the device into their tenant.
    claimed_by_tenant    TEXT REFERENCES tenants(id) ON DELETE CASCADE,
    claimed_at           TIMESTAMPTZ,

    -- Set when the certificate has been handed to the device. Terminal:
    -- a second delivery needs an explicit re-pair, so a leaked claim token
    -- cannot be redeemed twice.
    cert_delivered_at    TIMESTAMPTZ,

    first_seen_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at         TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- The key is half the row identity, so it cannot move underneath a
    -- pending claim: a different key is a different row.
    PRIMARY KEY (device_id, pubkey_hex),

    CONSTRAINT device_enrollments_pubkey_hex_shape
        CHECK (pubkey_hex ~ '^[0-9a-f]{64}$'),
    CONSTRAINT device_enrollments_device_id_shape
        CHECK (device_id ~ '^thesada-[0-9a-f]{12}$')
);

-- Anyone on the internet can create rows here, so the pruning sweep needs to
-- find stale ones cheaply.
CREATE INDEX device_enrollments_last_seen_idx
    ON device_enrollments (last_seen_at);

-- Grants. thesada_app_admin only: the table has no RLS, and EnrollmentService
-- is the sole consumer and runs every statement on the admin pool through
-- db.WithAdminAudit. Handing thesada_app the same grant would put an
-- unscoped table behind the tenant-scoped role, where nothing constrains a
-- future query to one tenant. The ingest role never touches enrollments.
GRANT SELECT, INSERT, UPDATE, DELETE ON device_enrollments TO thesada_app_admin;
