//go:build integration

// 0048 moves every stored "" WiFi password into device_open_networks and leaves
// no empty value in device_config_secrets. Run on seeded rows as the migrate role.
//
//	go test -tags integration -run TestMigration0048 ./migrations/...
package migrations_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"thesada.app/app/migrations"
	"thesada.app/app/pkg/service/servicetest"
)

func TestMigration0048_MovesEmptyWifiRows(t *testing.T) {
	ctx := context.Background()
	super, baseURL := servicetest.StartPostgres(t)
	servicetest.BootstrapProdRoles(t, super)
	migrator := servicetest.OpenAs(t, baseURL, "thesada_app")
	if err := migrations.Apply(ctx, migrator); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	body, err := migrations.FS.ReadFile("0048_device_open_networks.sql")
	if err != nil {
		t.Fatalf("read 0048: %v", err)
	}

	// Back to the shape before 0048, then rows as the old store left them.
	if _, err := super.Exec(ctx, `
		ALTER TABLE device_config_secrets DROP CONSTRAINT device_config_secrets_not_empty;
		DROP TABLE device_open_networks;
		ALTER TABLE devices DROP COLUMN config_changed_at, DROP COLUMN config_read_at;
		INSERT INTO tenants (id, display_name) VALUES ('m48', 'm48');`); err != nil {
		t.Fatalf("undo 0048: %v", err)
	}
	var dev string
	if err := super.QueryRow(ctx,
		`INSERT INTO devices (tenant_id, device_id) VALUES ('m48', 'd1') RETURNING id::text`).Scan(&dev); err != nil {
		t.Fatalf("seed device: %v", err)
	}
	empty, real := bytes.Repeat([]byte{1}, 28), bytes.Repeat([]byte{2}, 40)
	for _, r := range []struct {
		device any
		field  string
		blob   []byte
	}{
		{dev, "wifi.password:cafe", empty},
		{dev, "wifi.password:home", real},
		{dev, "wifi.password", empty},
		{nil, "mqtt.password", empty},
	} {
		if _, err := super.Exec(ctx,
			`INSERT INTO device_config_secrets (tenant_id, device_pk, field, ciphertext) VALUES ('m48', $1, $2, $3)`,
			r.device, r.field, r.blob); err != nil {
			t.Fatalf("seed %s: %v", r.field, err)
		}
	}

	if err := pgx.BeginFunc(ctx, migrator, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, string(body))
		return err
	}); err != nil {
		t.Fatalf("run 0048: %v", err)
	}

	var ssid, source string
	var n int
	if err := super.QueryRow(ctx,
		`SELECT count(*) OVER (), ssid, source FROM device_open_networks WHERE device_pk = $1`, dev).Scan(&n, &ssid, &source); err != nil {
		t.Fatalf("read markers: %v", err)
	}
	if n != 1 || ssid != "cafe" || source != "migration" {
		t.Errorf("markers = %d, %q, %q, want one cafe marker from the migration", n, ssid, source)
	}
	var fields []string
	rows, err := super.Query(ctx, `SELECT field FROM device_config_secrets ORDER BY field`)
	if err != nil {
		t.Fatalf("read secrets: %v", err)
	}
	for rows.Next() {
		var f string
		if err := rows.Scan(&f); err != nil {
			t.Fatal(err)
		}
		fields = append(fields, f)
	}
	rows.Close()
	if len(fields) != 1 || fields[0] != "wifi.password:home" {
		t.Errorf("secrets left = %v, want only wifi.password:home", fields)
	}
	if _, err := super.Exec(ctx,
		`INSERT INTO device_config_secrets (tenant_id, device_pk, field, ciphertext) VALUES ('m48', $1, 'web.password', $2)`,
		dev, empty); err == nil {
		t.Error("an empty value was stored after 0048")
	}
}
