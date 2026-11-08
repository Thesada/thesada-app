-- 0041_cert_pubkey_backfill_rls: rerun the 0031 pubkey_hex backfill as the
-- BYPASSRLS role.
-- WHY: device_certificates and devices are FORCE RLS and migrate runs as
-- their owner, which does not bypass it. 0031's UPDATE ran with no tenant
-- set and matched no rows. Same rule as 0031: a device id
-- with two claimed keys stays null. Rerunning is a no-op (pubkey_hex IS NULL).
-- Needs: GRANT thesada_app_admin TO thesada_app (docs/runbook.md, Migrations).
-- Rollback: none needed, the column was meant to hold these values.

-- The old app keeps serving during migrate: fail fast rather than queue it.
SET LOCAL lock_timeout = '5s';

SET LOCAL ROLE thesada_app_admin;

DO $$
BEGIN
    IF NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION '0041 needs a role that bypasses RLS, got %', current_user;
    END IF;
END $$;

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

RESET ROLE;
