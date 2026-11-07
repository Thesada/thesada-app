//go:build integration

// A retained sensor delivery is a broker replay, so it must not count as the
// device talking.
//
//	go test -tags integration -run TestHandleSensor ./pkg/mqtt/...
package mqtt

import (
	"context"
	"testing"
	"time"

	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/ws"
)

func TestHandleSensor_RetainedReplayIsNotALiveReading(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	const tenant, dev = "sens-ret", "dev-ret"
	env.SeedTenant(t, tenant)
	pk, err := env.Services.Devices.Upsert(tenant, dev, "", "", "", "thesada/"+tenant+"/"+dev)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	// Quiet for an hour, with its absence alert still open.
	if _, err := env.Super.Exec(ctx,
		`UPDATE devices SET last_seen_at = now() - interval '1 hour' WHERE id = $1`, pk); err != nil {
		t.Fatalf("age device: %v", err)
	}
	if _, err := env.Super.Exec(ctx,
		`INSERT INTO device_alerts (device_pk, severity, code, message)
		 VALUES ($1, 'warn', 'absence', 'no contact')`, pk); err != nil {
		t.Fatalf("seed absence: %v", err)
	}

	state := func() (seen time.Time, rows int, absenceOpen bool) {
		t.Helper()
		if err := env.Super.QueryRow(ctx, `
			SELECT d.last_seen_at,
			       (SELECT count(*) FROM device_telemetry WHERE device_pk = d.id),
			       EXISTS (SELECT 1 FROM device_alerts
			               WHERE device_pk = d.id AND code = 'absence' AND cleared_at IS NULL)
			FROM devices d WHERE d.id = $1`, pk).Scan(&seen, &rows, &absenceOpen); err != nil {
			t.Fatalf("read device state: %v", err)
		}
		return seen, rows, absenceOpen
	}
	before, _, _ := state()

	c := &Client{services: env.Services, hub: ws.New(env.Cfg)}
	c.handleSensor(tenant, dev, "temp", []byte("21.5"), true)
	if seen, rows, open := state(); !seen.Equal(before) || rows != 0 || !open {
		t.Fatalf("retained replay: last_seen moved=%v telemetry=%d absence_open=%v, want unchanged/0/true",
			!seen.Equal(before), rows, open)
	}

	// Control: the same reading delivered live does all three.
	c.handleSensor(tenant, dev, "temp", []byte("21.5"), false)
	if seen, rows, open := state(); !seen.After(before) || rows != 1 || open {
		t.Fatalf("live reading: last_seen advanced=%v telemetry=%d absence_open=%v, want true/1/false",
			seen.After(before), rows, open)
	}
}
