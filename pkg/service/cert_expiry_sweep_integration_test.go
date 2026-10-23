//go:build integration

package service_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service/servicetest"
)

// One cert_expiring warn per soon-expiring active certificate, none for a cert
// with time left, and the alert clears once that certificate is revoked.
func TestCertExpirySweep_OneWarnPerCertAndClearOnRevoke(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	env.SeedTenant(t, "cx-a")
	now := time.Now()
	soon := seedCertDevice(t, env, "cx-a", "thesada-cx-soon", "cx-soon", now.Add(10*24*time.Hour))
	later := seedCertDevice(t, env, "cx-a", "thesada-cx-later", "cx-later", now.Add(200*24*time.Hour))

	env.Services.Alerts.RaiseCertExpiriesAny(ctx)
	env.Services.Alerts.RaiseCertExpiriesAny(ctx)
	if n := certExpiryAlerts(t, env, soon, false); n != 1 {
		t.Fatalf("soon alerts = %d, want 1", n)
	}
	if n := certExpiryAlerts(t, env, later, false); n != 0 {
		t.Fatalf("later alerts = %d, want 0", n)
	}
	gone := seedCertDevice(t, env, "cx-a", "thesada-cx-gone", "cx-gone", now.Add(-48*time.Hour))
	env.Services.Alerts.RaiseCertExpiriesAny(ctx)
	var msg string
	if err := env.Super.QueryRow(ctx,
		`SELECT message FROM device_alerts WHERE device_pk = $1 AND code = 'cert_expiring'`, gone).Scan(&msg); err != nil {
		t.Fatalf("expired cert alert: %v", err)
	}
	if !strings.Contains(msg, "expired") {
		t.Fatalf("expired cert message %q", msg)
	}

	if err := env.Services.Certificates.Revoke(ctx, "cx-a", soon); err != nil {
		t.Fatal(err)
	}
	env.Services.Alerts.RaiseCertExpiriesAny(ctx)
	if n := certExpiryAlerts(t, env, soon, true); n != 1 {
		t.Fatalf("cleared alerts after revoke = %d, want 1", n)
	}
}

// seedCertDevice inserts a paired device with one active cert expiring at notAfter.
// in: t, env, tenant, device id, serial, expiry. out: device pk.
func seedCertDevice(t *testing.T, env *servicetest.Env, tenant, deviceID, serial string, notAfter time.Time) uuid.UUID {
	t.Helper()
	ctx := context.Background()
	pk, err := env.Services.Devices.Upsert(tenant, deviceID, "", "", "", "thesada/"+tenant+"/"+deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Services.Certificates.Issue(ctx, tenant, pk, serial, serial+"-cn", time.Now().Add(-time.Hour), notAfter, "pem"); err != nil {
		t.Fatal(err)
	}
	return pk
}

// certExpiryAlerts counts cert_expiring alerts for a device, cleared or open.
// in: t, env, device pk, cleared. out: count.
func certExpiryAlerts(t *testing.T, env *servicetest.Env, pk uuid.UUID, cleared bool) int {
	t.Helper()
	var n int
	if err := env.Super.QueryRow(context.Background(),
		`SELECT count(*) FROM device_alerts WHERE device_pk = $1 AND code = 'cert_expiring'
		   AND (cleared_at IS NOT NULL) = $2`, pk, cleared).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}
