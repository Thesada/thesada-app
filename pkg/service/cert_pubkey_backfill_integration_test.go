//go:build integration

package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/migrations"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// mig0041Apply runs the 0041 body as the runner does, on the production
// migrate role (thesada_app: owner, NOBYPASSRLS, FORCE RLS on).
func mig0041Apply(t *testing.T, env *servicetest.Env) error {
	t.Helper()
	body, err := migrations.FS.ReadFile("0041_cert_pubkey_backfill_rls.sql")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return pgx.BeginFunc(ctx, env.Pools.App, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, string(body))
		return err
	})
}

// TestMigration0041_BackfillsPubkeyUnderTheProductionRole: the 0031 rule
// fills null pubkeys once the data step runs as the BYPASSRLS role.
func TestMigration0041_BackfillsPubkeyUnderTheProductionRole(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	const tenant, other = "mig41", "mig41-other"
	env.SeedTenant(t, tenant)
	env.SeedTenant(t, other)
	keyA, keyB, keyC := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	const oneID, twoID, unclaimedID, keptID = "thesada-0000000041a1", "thesada-0000000041a2", "thesada-0000000041a3", "thesada-0000000041a4"
	const foreignID, movedID = "thesada-0000000041a5", "thesada-0000000041a6"
	pks := map[string]uuid.UUID{}
	for _, id := range []string{oneID, twoID, unclaimedID, keptID, foreignID, movedID} {
		pk, err := env.Services.Devices.Upsert(tenant, id, "", "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		pks[id] = pk
	}
	enrollIn := func(owner, id, key string, claimed bool) {
		t.Helper()
		if _, err := env.Super.Exec(ctx,
			`INSERT INTO device_enrollments (device_id, pubkey_hex, claim_token_hash, verified_at, claimed_by_tenant, claimed_at)
			 VALUES ($1, $2, 'h', now(), $3, CASE WHEN $4 THEN now() END)`,
			id, key, owner, claimed); err != nil {
			t.Fatalf("seed enrollment %s: %v", id, err)
		}
	}
	enroll := func(id, key string, claimed bool) { t.Helper(); enrollIn(tenant, id, key, claimed) }
	enroll(oneID, keyA, true)
	enroll(twoID, keyA, true)
	enroll(twoID, keyB, true)
	enroll(unclaimedID, keyA, false)
	enroll(keptID, keyA, true)
	// Only another tenant's leftover enrollment for the id: its key is not this cert's.
	enrollIn(other, foreignID, keyB, true)
	// Claimed into this tenant after its cert was issued, as after a reassignment.
	enroll(movedID, keyA, true)
	seedCert(t, env, pks[oneID], "41a1", service.DeviceCertCN(tenant, oneID), true, 0)
	seedCert(t, env, pks[twoID], "41a2", service.DeviceCertCN(tenant, twoID), true, 0)
	seedCert(t, env, pks[unclaimedID], "41a3", service.DeviceCertCN(tenant, unclaimedID), true, 0)
	seedCert(t, env, pks[keptID], "41a4", service.DeviceCertCN(tenant, keptID), false, 0)
	seedCert(t, env, pks[foreignID], "41a5", service.DeviceCertCN(tenant, foreignID), true, 0)
	seedCert(t, env, pks[movedID], "41a6", service.DeviceCertCN(tenant, movedID), true, 24*time.Hour)
	if _, err := env.Super.Exec(ctx, `UPDATE device_certificates SET pubkey_hex = $1 WHERE serial_hex = '41a4'`, keyC); err != nil {
		t.Fatal(err)
	}

	want := map[string]string{"41a1": keyA, "41a2": "", "41a3": "", "41a4": keyC, "41a5": "", "41a6": ""}
	for run := 1; run <= 2; run++ {
		if err := mig0041Apply(t, env); err != nil {
			t.Fatalf("apply 0041 as thesada_app (run %d): %v", run, err)
		}
		for serial, key := range want {
			var got *string
			if err := env.Super.QueryRow(ctx,
				`SELECT pubkey_hex FROM device_certificates WHERE serial_hex = $1`, serial).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if (got == nil && key != "") || (got != nil && *got != key) {
				t.Errorf("run %d cert %s: pubkey_hex %v, want %q", run, serial, got, key)
			}
		}
	}
}
