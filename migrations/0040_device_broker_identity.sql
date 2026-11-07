-- 0040_device_broker_identity: record the tenant a device's broker identity
-- was issued under, and keep that identity on one device row.
-- WHY: the dynsec client (thesada-<tenant>-<device_id>), its role and the
-- cert CN carry the tenant at issue time. A reassign moves the devices row
-- but not those, so a teardown that rebuilds the names from the current
-- tenant misses them and leaves a deleted device's client live. The old
-- tenant could also claim the same device_id again and be issued a cert for
-- the unit's live CN. Both unique indexes refuse that second identity.
-- broker_stale_tenants lists older identities a teardown still has to delete.
-- Rollback: DROP INDEX device_certificates_live_cn_uniq,
-- devices_broker_identity_uniq; ALTER TABLE devices DROP COLUMN
-- broker_tenant_id, DROP COLUMN broker_stale_tenants.

-- The old app keeps serving during migrate: fail fast rather than queue it.
SET LOCAL lock_timeout = '5s';

-- No FK: an identity outlives a deleted tenant until its teardown runs.
ALTER TABLE devices
    ADD COLUMN broker_tenant_id TEXT,
    ADD COLUMN broker_stale_tenants TEXT[] NOT NULL DEFAULT '{}';

-- devices and device_certificates are FORCE RLS and migrate runs as their
-- owner, which does not bypass it. The data steps run as the BYPASSRLS role.
SET LOCAL ROLE thesada_app_admin;

DO $$
BEGIN
    IF NOT (SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user) THEN
        RAISE EXCEPTION '0040 needs a role that bypasses RLS, got %', current_user;
    END IF;
END $$;

-- Certs issued before issueTx superseded (2026-07-20) can leave one device
-- several unrevoked rows. Newest wins, as GetActive and issueTx already do.
UPDATE device_certificates c
   SET revoked = true, revoked_at = now()
 WHERE NOT c.revoked
   AND EXISTS (SELECT 1 FROM device_certificates n
                WHERE n.device_pk = c.device_pk AND NOT n.revoked
                  AND (n.created_at, n.id) > (c.created_at, c.id));

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM device_certificates WHERE NOT revoked
                GROUP BY cn HAVING count(DISTINCT device_pk) > 1) THEN
        RAISE EXCEPTION 'two devices hold an unrevoked certificate with the same CN, resolve before migrating'
            USING HINT = 'SELECT cn, array_agg(DISTINCT device_pk) FROM device_certificates WHERE NOT revoked GROUP BY cn HAVING count(DISTINCT device_pk) > 1';
    END IF;
END $$;

-- The live cert names the current identity: one per device, one CN per device.
-- CNs read 'thesada-' || tenant || '-' || device_id.
UPDATE devices d
   SET broker_tenant_id = substr(c.cn, 9, length(c.cn) - 9 - length(d.device_id))
  FROM device_certificates c
 WHERE c.device_pk = d.id AND NOT c.revoked
   AND c.cn LIKE 'thesada-%'
   AND right(c.cn, length(d.device_id) + 1) = '-' || d.device_id
   AND length(c.cn) > 9 + length(d.device_id);

-- A revoked cert under any other tenant may have left its client behind: old
-- code tore down and re-paired under the current tenant only. Skipped where
-- another row holds that tenant's id, which then owns that identity.
UPDATE devices d
   SET broker_stale_tenants = s.tenants
  FROM (SELECT r.device_pk, array_agg(DISTINCT r.tenant ORDER BY r.tenant) AS tenants
          FROM (SELECT c.device_pk, dd.device_id, dd.tenant_id, dd.broker_tenant_id,
                       substr(c.cn, 9, length(c.cn) - 9 - length(dd.device_id)) AS tenant
                  FROM device_certificates c
                  JOIN devices dd ON dd.id = c.device_pk
                 WHERE c.revoked
                   AND c.cn LIKE 'thesada-%'
                   AND right(c.cn, length(dd.device_id) + 1) = '-' || dd.device_id
                   AND length(c.cn) > 9 + length(dd.device_id)) r
         WHERE r.tenant <> coalesce(r.broker_tenant_id, r.tenant_id)
           AND NOT EXISTS (SELECT 1 FROM devices o
                            WHERE o.device_id = r.device_id AND o.id <> r.device_pk
                              AND (o.tenant_id = r.tenant OR o.broker_tenant_id = r.tenant))
         GROUP BY r.device_pk) s
 WHERE s.device_pk = d.id;

RESET ROLE;

CREATE UNIQUE INDEX devices_broker_identity_uniq
    ON devices (broker_tenant_id, device_id) WHERE broker_tenant_id IS NOT NULL;

CREATE UNIQUE INDEX device_certificates_live_cn_uniq
    ON device_certificates (cn) WHERE NOT revoked;
