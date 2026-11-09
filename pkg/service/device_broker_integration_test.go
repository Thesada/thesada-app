//go:build integration

// Broker identity: the tenant a device's dynsec client and cert CN were issued
// under is recorded, survives a reassign, and is held by one device row.
//
//	go test -tags integration -run 'TestBrokerIdentity|TestCertificates_LiveCN|TestMigration0040' ./pkg/service/...
package service_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/migrations"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

const brokerDevID = "thesada-0b0b0b0b0b0b"

// brokerTenants seeds the issuing and target tenants and a device row in the first.
func brokerTenants(t *testing.T, env *servicetest.Env, a, b string) uuid.UUID {
	t.Helper()
	env.SeedTenant(t, a)
	env.SeedTenant(t, b)
	pk, err := env.Services.Devices.Upsert(a, brokerDevID, "", "", "", "")
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	return pk
}

// identityOf reads a device row's recorded identity: current ("" for NULL)
// and the stale list.
func identityOf(t *testing.T, env *servicetest.Env, pk uuid.UUID) (string, []string) {
	t.Helper()
	var current *string
	var stale []string
	if err := env.Super.QueryRow(context.Background(),
		`SELECT broker_tenant_id, broker_stale_tenants FROM devices WHERE id = $1`, pk).Scan(&current, &stale); err != nil {
		t.Fatal(err)
	}
	if current == nil {
		return "", stale
	}
	return *current, stale
}

// loadDevice reloads a device row.
func loadDevice(t *testing.T, env *servicetest.Env, pk uuid.UUID) *service.Device {
	t.Helper()
	d, err := env.Services.Devices.GetByIDAny(context.Background(), pk)
	if err != nil || d == nil {
		t.Fatalf("load device %s: %v", pk, err)
	}
	return d
}

func TestBrokerIdentity_SurvivesReassignAndStaysOnOneRow(t *testing.T) {
	env := servicetest.Start(t)
	dev := env.Services.Devices
	ctx := context.Background()
	const a, b = "broker-a", "broker-b"
	pk := brokerTenants(t, env, a, b)

	if id, err := dev.ReserveBrokerIdentity(ctx, a, brokerDevID); err != nil || id.Current != a || len(id.Stale) != 0 {
		t.Fatalf("first reserve = %+v, %v", id, err)
	}
	if err := dev.Reassign(ctx, pk, b); err != nil {
		t.Fatal(err)
	}
	if id, err := dev.BrokerIdentityOf(ctx, loadDevice(t, env, pk)); err != nil || id.Current != a {
		t.Fatalf("identity after reassign = %+v, %v, want %s", id, err, a)
	}

	// A new row in the old tenant (ingest, or a claim) gets no identity of its own.
	phantomPk, err := dev.Upsert(a, brokerDevID, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := dev.ReserveBrokerIdentity(ctx, a, brokerDevID); !errors.Is(err, service.ErrBrokerIdentityTaken) {
		t.Fatalf("reserve for the phantom row = %v, want ErrBrokerIdentityTaken", err)
	}
	if id, err := dev.BrokerIdentityOf(ctx, loadDevice(t, env, phantomPk)); err != nil || len(id.Tenants()) != 0 {
		t.Fatalf("identity of the phantom = %+v, %v, want none", id, err)
	}

	// Re-issue under the new tenant keeps the old identity recorded as stale,
	// and the phantom stays refused until that one is gone.
	if id, err := dev.ReserveBrokerIdentity(ctx, b, brokerDevID); err != nil || id.Current != b || !slices.Equal(id.Stale, []string{a}) {
		t.Fatalf("reserve in the new tenant = %+v, %v, want current %s stale [%s]", id, err, b, a)
	}
	if _, err := dev.ReserveBrokerIdentity(ctx, a, brokerDevID); !errors.Is(err, service.ErrBrokerIdentityTaken) {
		t.Fatalf("reserve for the phantom while the old identity is stale = %v, want ErrBrokerIdentityTaken", err)
	}
	if err := dev.ForgetBrokerIdentity(ctx, b, pk, a); err != nil {
		t.Fatal(err)
	}
	if current, stale := identityOf(t, env, pk); current != b || len(stale) != 0 {
		t.Fatalf("after forgetting the stale one = %q %v, want %s []", current, stale, b)
	}
	if _, err := dev.ReserveBrokerIdentity(ctx, a, brokerDevID); err != nil {
		t.Fatalf("reserve for the old tenant once freed = %v, want nil", err)
	}
}

// A row with no recorded identity (pre-0040 pairing) keeps the old tenant's
// identity through a reassign instead of reading as the new tenant's.
func TestBrokerIdentity_ReassignPinsAnUnrecordedIdentityToTheOldTenant(t *testing.T) {
	env := servicetest.Start(t)
	dev := env.Services.Devices
	ctx := context.Background()
	const a, b = "broker-pin-a", "broker-pin-b"
	pk := brokerTenants(t, env, a, b)
	if current, _ := identityOf(t, env, pk); current != "" {
		t.Fatalf("seeded row already pinned to %q", current)
	}
	if err := dev.Reassign(ctx, pk, b); err != nil {
		t.Fatal(err)
	}
	if current, stale := identityOf(t, env, pk); current != a || len(stale) != 0 {
		t.Fatalf("after reassign = %q %v, want pinned to %s", current, stale, a)
	}
	if id, err := dev.BrokerIdentityOf(ctx, loadDevice(t, env, pk)); err != nil || id.Current != a {
		t.Fatalf("identity after reassign = %+v, %v, want %s", id, err, a)
	}
	// A second move keeps the pin: the identity still carries the first tenant.
	const c = "broker-pin-c"
	env.SeedTenant(t, c)
	if err := dev.Reassign(ctx, pk, c); err != nil {
		t.Fatal(err)
	}
	if current, stale := identityOf(t, env, pk); current != a || len(stale) != 0 {
		t.Fatalf("after the second reassign = %q %v, want still %s", current, stale, a)
	}
}

// The unpinned fallback reads the row's tenant, and a stale snapshot from
// another tenant gets no current identity, so teardown touches neither.
func TestBrokerIdentityOf_UnpinnedFallsBackToTheRowsTenant(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	const a, b = "broker-snap-a", "broker-snap-b"
	pk := brokerTenants(t, env, a, b)
	snapshot := loadDevice(t, env, pk)
	if _, err := env.Super.Exec(ctx, `UPDATE devices SET tenant_id = $1 WHERE id = $2`, b, pk); err != nil {
		t.Fatal(err)
	}
	if id, err := env.Services.Devices.BrokerIdentityOf(ctx, snapshot); !errors.Is(err, service.ErrBrokerSnapshotStale) || id.Current != "" {
		t.Fatalf("identity from a stale snapshot = %+v, %v, want ErrBrokerSnapshotStale", id, err)
	}
	if id, err := env.Services.Devices.BrokerIdentityOf(ctx, loadDevice(t, env, pk)); err != nil || id.Current != b {
		t.Fatalf("identity = %+v, %v, want the row's tenant %s", id, err, b)
	}
}

func TestBrokerIdentity_FormerTenantCannotClaimTheID(t *testing.T) {
	for _, stale := range []bool{false, true} {
		name := "current"
		if stale {
			name = "stale"
		}
		t.Run(name, func(t *testing.T) {
			env := servicetest.Start(t)
			ctx := context.Background()
			const a, b = "broker-claim-a", "broker-claim-b"
			pk := brokerTenants(t, env, a, b)
			owner := seedUser(t, env, a, "owner@broker-claim-a.test")
			if _, err := env.Services.Devices.ReserveBrokerIdentity(ctx, a, brokerDevID); err != nil {
				t.Fatal(err)
			}
			if err := env.Services.Devices.Reassign(ctx, pk, b); err != nil {
				t.Fatal(err)
			}
			if stale {
				if _, err := env.Services.Devices.ReserveBrokerIdentity(ctx, b, brokerDevID); err != nil {
					t.Fatal(err)
				}
			}
			seedEnrollRows(t, env, brokerDevID, enrollSeed{"c", "", false})
			_, err := env.Services.Enrollments.ClaimInto(ctx, brokerDevID, strings.Repeat("c", 64), a, owner,
				service.DeviceTopicPrefix("thesada", a, brokerDevID))
			if !errors.Is(err, service.ErrBrokerIdentityTaken) {
				t.Fatalf("claim by the former tenant = %v, want ErrBrokerIdentityTaken", err)
			}
			var rows int
			if err := env.Super.QueryRow(ctx,
				`SELECT count(*) FROM devices WHERE tenant_id = $1 AND device_id = $2`, a, brokerDevID).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if rows != 0 {
				t.Fatalf("refused claim left %d device rows in the former tenant", rows)
			}
		})
	}
}

func TestCertificates_LiveCNStaysOnOneRow(t *testing.T) {
	env := servicetest.Start(t)
	certs := env.Services.Certificates
	ctx := context.Background()
	const a, b = "broker-cert-a", "broker-cert-b"
	pk := brokerTenants(t, env, a, b)
	cn := service.DeviceCertCN(a, brokerDevID)
	now := time.Now()
	issue := func(tenant string, devicePk uuid.UUID, serial string) error {
		return certs.IssueWithIdentity(ctx, tenant, devicePk, serial, cn, now, now.Add(time.Hour), "pem", strings.Repeat("a", 64))
	}
	if err := issue(a, pk, "a1"); err != nil {
		t.Fatal(err)
	}
	if err := issue(a, pk, "a2"); err != nil {
		t.Fatalf("re-issue on the same row = %v, want nil", err)
	}
	if err := env.Services.Devices.Reassign(ctx, pk, b); err != nil {
		t.Fatal(err)
	}
	phantomPk, err := env.Services.Devices.Upsert(a, brokerDevID, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := issue(a, phantomPk, "a3"); !errors.Is(err, service.ErrCertCNLive) {
		t.Fatalf("enrollment issue for the phantom = %v, want ErrCertCNLive", err)
	}
	if err := certs.Issue(ctx, a, phantomPk, "a4", cn, now, now.Add(time.Hour), "pem"); !errors.Is(err, service.ErrCertCNLive) {
		t.Fatalf("admin issue for the phantom = %v, want ErrCertCNLive", err)
	}
	if err := certs.Revoke(ctx, b, pk); err != nil {
		t.Fatal(err)
	}
	if err := issue(a, phantomPk, "a5"); err != nil {
		t.Fatalf("issue once the unit's cert is revoked = %v, want nil", err)
	}
}

// mig0040Revert drops what 0040 adds, so the test can seed the pre-0040 shape.
func mig0040Revert(t *testing.T, env *servicetest.Env) {
	t.Helper()
	if _, err := env.Super.Exec(context.Background(), `
		DROP INDEX device_certificates_live_cn_uniq;
		DROP INDEX devices_broker_identity_uniq;
		ALTER TABLE devices DROP COLUMN broker_tenant_id, DROP COLUMN broker_stale_tenants;`); err != nil {
		t.Fatalf("revert 0040: %v", err)
	}
}

// mig0040Apply runs the 0040 body the way the runner does, in one tx on the
// production migrate role (thesada_app: owner, NOBYPASSRLS, FORCE RLS on).
func mig0040Apply(t *testing.T, env *servicetest.Env) error {
	t.Helper()
	body, err := migrations.FS.ReadFile("0040_device_broker_identity.sql")
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

// seedCert inserts a cert row the way pre-0040 code could leave it.
func seedCert(t *testing.T, env *servicetest.Env, pk uuid.UUID, serial, cn string, revoked bool, age time.Duration) {
	t.Helper()
	if _, err := env.Super.Exec(context.Background(),
		`INSERT INTO device_certificates (device_pk, serial_hex, cn, not_before, not_after, cert_pem, status, revoked, created_at)
		 VALUES ($1, $2, $3, now(), now() + interval '1 hour', 'pem', 'active', $4, now() - $5::interval)`,
		pk, serial, cn, revoked, age.String()); err != nil {
		t.Fatalf("seed cert %s: %v", serial, err)
	}
}

// TestMigration0040_BackfillsUnderTheProductionRole reruns 0040 as thesada_app
// over pre-0040 rows: every legacy shape lands where teardown will look.
func TestMigration0040_BackfillsUnderTheProductionRole(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	const a, b, c = "mig-a", "mig-b", "mig-c"
	for _, tn := range []string{a, b, c} {
		env.SeedTenant(t, tn)
	}
	cnOf := func(tenant, id string) string { return service.DeviceCertCN(tenant, id) }
	upsert := func(tenant, id string) uuid.UUID {
		pk, err := env.Services.Devices.Upsert(tenant, id, "", "", "", "")
		if err != nil {
			t.Fatal(err)
		}
		return pk
	}
	const movedID, homeID, bareID, dupID, revokedID, repairedID, heldID = "thesada-0000000000a1", "thesada-0000000000a2",
		"thesada-0000000000a3", "thesada-0000000000a4", "thesada-0000000000a5", "thesada-0000000000a6", "thesada-0000000000a7"
	moved, home, bare, dup := upsert(b, movedID), upsert(b, homeID), upsert(b, bareID), upsert(a, dupID)
	revoked, repaired, held := upsert(b, revokedID), upsert(b, repairedID), upsert(b, heldID)
	upsert(c, heldID)

	mig0040Revert(t, env)
	seedCert(t, env, moved, "c1", cnOf(a, movedID), false, 0)       // reassigned, still on its A cert
	seedCert(t, env, home, "c2", cnOf(b, homeID), false, 0)         // never moved
	seedCert(t, env, dup, "c3", cnOf(a, dupID), false, 2*time.Hour) // paired twice before supersede
	seedCert(t, env, dup, "c4", cnOf(a, dupID), false, time.Hour)   // the newer one wins
	seedCert(t, env, revoked, "c5", cnOf(a, revokedID), true, 0)    // reassigned, then revoked
	seedCert(t, env, repaired, "c6", cnOf(a, repairedID), true, time.Hour)
	seedCert(t, env, repaired, "c7", cnOf(b, repairedID), false, 0) // re-paired in B, A left behind
	seedCert(t, env, held, "c8", cnOf(c, heldID), true, 0)          // C has its own row for the id

	if err := mig0040Apply(t, env); err != nil {
		t.Fatalf("apply 0040 as thesada_app: %v", err)
	}
	for _, w := range []struct {
		name    string
		pk      uuid.UUID
		current string
		stale   []string
	}{
		{"moved", moved, a, nil},
		{"home", home, b, nil},
		{"bare", bare, "", nil},
		{"duplicate", dup, a, nil},
		{"revoked after reassign", revoked, "", []string{a}},
		{"re-paired after reassign", repaired, b, []string{a}},
		{"other tenant holds the id", held, "", nil},
	} {
		current, stale := identityOf(t, env, w.pk)
		if current != w.current || !slices.Equal(stale, w.stale) && len(stale)+len(w.stale) > 0 {
			t.Errorf("%s: identity %q %v, want %q %v", w.name, current, stale, w.current, w.stale)
		}
	}
	var live int
	if err := env.Super.QueryRow(ctx,
		`SELECT count(*) FROM device_certificates WHERE device_pk = $1 AND NOT revoked AND serial_hex = 'c4'`, dup).Scan(&live); err != nil || live != 1 {
		t.Errorf("duplicate collapse kept %d live newest rows, %v, want 1", live, err)
	}

	mig0040Revert(t, env)
	seedCert(t, env, bare, "c9", cnOf(a, movedID), false, 0)
	if err := mig0040Apply(t, env); err == nil || !strings.Contains(err.Error(), "same CN") {
		t.Fatalf("0040 over a CN two devices hold = %v, want the same-CN refusal", err)
	}

	// A session holding devices makes the ALTER give up instead of queueing
	// every later device write behind it.
	if _, err := env.Super.Exec(ctx, `DELETE FROM device_certificates WHERE serial_hex = 'c9'`); err != nil {
		t.Fatal(err)
	}
	hold, err := env.Super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = hold.Rollback(ctx) }()
	if _, err := hold.Exec(ctx, `SELECT 1 FROM devices LIMIT 1`); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := mig0040Apply(t, env); err == nil || !strings.Contains(err.Error(), "lock timeout") {
		t.Fatalf("0040 under a held lock = %v, want a lock timeout", err)
	}
	if d := time.Since(start); d > 15*time.Second {
		t.Fatalf("0040 waited %v on the held lock", d)
	}
}
