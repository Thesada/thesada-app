package service

import (
	"context"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// Test-only seam. export_test.go compiles into the test binary and nowhere
// else, so this cannot be reached from production code.

// SetVerifyBurnHook installs f in the window between the challenge burn and
// the verified update, and returns a function restoring the previous value.
func SetVerifyBurnHook(f func()) func() {
	prev := testHookAfterBurn
	testHookAfterBurn = f
	return func() { testHookAfterBurn = prev }
}

// PlantLegacyWifi stores a device row under the bare wifi.password, which SetSecret refuses,
// the way a pre-per-SSID build left it.
func (s *SecretService) PlantLegacyWifi(ctx context.Context, tenantID string, devicePk uuid.UUID, value string) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return s.setSecretTx(ctx, tx, tenantID, devicePk, LegacyWifiPassword, value)
	})
}
