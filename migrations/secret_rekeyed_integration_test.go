//go:build integration

// 0049 adds device_config_secrets.rekeyed: rows that predate it read false, its rollback
// drops it again, and it applies twice over. Run as the migrate role.
//
//	go test -tags integration -run TestMigration0049 ./migrations/...
package migrations_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"thesada.app/app/migrations"
	"thesada.app/app/pkg/service/servicetest"
)

const rollback0049 = `ALTER TABLE device_config_secrets DROP COLUMN rekeyed`

func TestMigration0049_RekeyedFlag(t *testing.T) {
	ctx := context.Background()
	super, baseURL := servicetest.StartPostgres(t)
	servicetest.BootstrapProdRoles(t, super)
	migrator := servicetest.OpenAs(t, baseURL, "thesada_app")
	if err := migrations.Apply(ctx, migrator); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	body, err := migrations.FS.ReadFile("0049_secret_rekeyed.sql")
	if err != nil {
		t.Fatalf("read 0049: %v", err)
	}
	run := func(sql string) error {
		return pgx.BeginFunc(ctx, migrator, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, sql)
			return err
		})
	}

	if err := run(rollback0049); err != nil {
		t.Fatalf("rollback 0049 as the migrate role: %v", err)
	}
	if _, err := super.Exec(ctx, `INSERT INTO tenants (id, display_name) VALUES ('m49', 'm49')`); err != nil {
		t.Fatal(err)
	}
	var dev string
	if err := super.QueryRow(ctx,
		`INSERT INTO devices (tenant_id, device_id) VALUES ('m49', 'd1') RETURNING id::text`).Scan(&dev); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if _, err := super.Exec(ctx,
		`INSERT INTO device_config_secrets (tenant_id, device_pk, field, ciphertext) VALUES ('m49', $1, 'wifi.password:home', $2)`,
		dev, bytes.Repeat([]byte{2}, 40)); err != nil {
		t.Fatalf("seed row: %v", err)
	}

	if err := run(string(body)); err != nil {
		t.Fatalf("run 0049: %v", err)
	}
	var rekeyed bool
	if err := super.QueryRow(ctx,
		`SELECT rekeyed FROM device_config_secrets WHERE device_pk = $1`, dev).Scan(&rekeyed); err != nil {
		t.Fatalf("read flag: %v", err)
	}
	if rekeyed {
		t.Error("a row from before 0049 reads as a re-key")
	}
	if _, err := super.Exec(ctx,
		`INSERT INTO device_config_secrets (tenant_id, device_pk, field, ciphertext, rekeyed) VALUES ('m49', $1, 'web.password', $2, NULL)`,
		dev, bytes.Repeat([]byte{3}, 40)); err == nil {
		t.Error("rekeyed accepted NULL")
	}

	if err := run(rollback0049); err != nil {
		t.Fatalf("rollback 0049: %v", err)
	}
	if err := run(string(body)); err != nil {
		t.Fatalf("0049 again after its rollback: %v", err)
	}
}
