-- 0031_cert_serial_tombstones.sql
--
-- WHY: a device holding a cert asks POST /devices/enroll/status, and the
-- answer is looked up by cert serial. Owner revoke leaves the certificate
-- row in place (revoked = true) but deletes the enrollment, so the identity
-- pubkey has to live on the certificate or the signature cannot be checked
-- after the revoke. Device delete cascades device_certificates, and without
-- a copy of the serial the same ask would come back unknown and the unit
-- would keep a cert for a device that no longer exists.
--
-- NO RLS. The status check is unauthenticated and has no tenant to set.
-- The table holds a serial, a device id and a public key, which the device
-- already has. Access is SELECT for the admin role (the status lookup) and
-- INSERT for the app role (the delete path). No UPDATE or DELETE: a serial
-- is remembered for good.

ALTER TABLE device_certificates
    ADD COLUMN pubkey_hex TEXT;

ALTER TABLE device_certificates
    ADD CONSTRAINT device_certificates_pubkey_hex_shape
        CHECK (pubkey_hex IS NULL OR pubkey_hex ~ '^[0-9a-f]{64}$');

-- Backfill from the one claimed key still on the enrollment row. A device
-- id with two claimed keys is left null rather than guessed. Certs whose
-- enrollment was already reset stay null and answer unknown.
UPDATE device_certificates c
   SET pubkey_hex = sub.pubkey_hex
  FROM (
      SELECT d.id AS device_pk, min(e.pubkey_hex) AS pubkey_hex
        FROM devices d
        JOIN device_enrollments e
          ON e.device_id = d.device_id
         AND e.verified_at IS NOT NULL
         AND e.claimed_at IS NOT NULL
       GROUP BY d.id
      HAVING count(DISTINCT e.pubkey_hex) = 1
  ) sub
 WHERE c.device_pk = sub.device_pk
   AND c.pubkey_hex IS NULL;

CREATE TABLE device_cert_serial_tombstones (
    serial_hex  TEXT PRIMARY KEY,
    device_id   TEXT NOT NULL,
    pubkey_hex  TEXT NOT NULL,
    deleted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT device_cert_serial_tombstones_serial_shape
        CHECK (serial_hex ~ '^[0-9a-f]{1,40}$' AND serial_hex !~ '^0.'),
    CONSTRAINT device_cert_serial_tombstones_pubkey_hex_shape
        CHECK (pubkey_hex ~ '^[0-9a-f]{64}$'),
    CONSTRAINT device_cert_serial_tombstones_device_id_shape
        CHECK (device_id ~ '^thesada-[0-9a-f]{12}$')
);

GRANT SELECT, INSERT ON device_cert_serial_tombstones TO thesada_app_admin;
GRANT INSERT ON device_cert_serial_tombstones TO thesada_app;
