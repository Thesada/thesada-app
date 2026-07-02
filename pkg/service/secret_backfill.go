// secret_backfill.go - one-shot migration of existing app-managed devices
// into the encrypted device-config-secrets store (#443 phase 7). For each
// device it reads the last stored config.json snapshot, extracts any
// plaintext secret values still present, writes them to the encrypted store
// (SetSecret), and re-blanks the stored config so no plaintext lingers in
// device_files.
//
// Limitations (documented, by design for v1):
//   - It can only recover plaintext that is still in the CURRENT device_files
//     snapshot. Since phase 4, every config ingest blanks config.json, so a
//     device whose config was re-ingested after the feature shipped has an
//     already-blank snapshot and nothing to extract - run backfill before
//     configs re-ingest, or re-pull the device config first.
//   - It does not purge plaintext from older device_file_history rows; that
//     residual-history hygiene is out of scope here.
package service

import (
	"context"
	"fmt"
	"log/slog"
)

// BackfillResult is the summary of a backfill sweep.
type BackfillResult struct {
	Devices         int // devices scanned
	DevicesMigrated int // devices that had at least one secret migrated
	Secrets         int // individual secret values written to the store
}

// BackfillDeviceSecrets sweeps every device (cross-tenant, admin pool),
// extracts plaintext secrets from its stored config, writes them to the
// encrypted store, and re-blanks the stored config. Idempotent: a device
// whose config is already blank contributes nothing and re-running is safe
// (SetSecret overwrites with the same value). Fails loudly if the feature is
// off rather than silently no-opping.
// in: ctx, secret/device/device-files services. out: summary, error.
func BackfillDeviceSecrets(ctx context.Context, secrets *SecretService, devices *DeviceService, files *DeviceFilesService) (BackfillResult, error) {
	var res BackfillResult
	if !secrets.Enabled() {
		return res, ErrSecretsDisabled
	}
	all, err := devices.ListAllForAdmin(ctx)
	if err != nil {
		return res, fmt.Errorf("backfill: list devices: %w", err)
	}
	for _, d := range all {
		res.Devices++
		snap, err := files.Latest(ctx, d.TenantID, d.ID, "config.json")
		if err != nil {
			return res, fmt.Errorf("backfill: read config %s/%s: %w", d.TenantID, d.DeviceID, err)
		}
		if snap == nil {
			continue
		}
		// Migrate the known secret fields into the encrypted store.
		found := extractConfigSecrets(snap.Content)
		for field, value := range found {
			if err := secrets.SetSecret(ctx, d.TenantID, d.ID, field, value); err != nil {
				return res, fmt.Errorf("backfill: set %s for %s/%s: %w", field, d.TenantID, d.DeviceID, err)
			}
			res.Secrets++
		}
		if len(found) > 0 {
			res.DevicesMigrated++
		}
		// Re-blank the stored config whenever it still holds ANY plaintext
		// secret - the allowlist fields above OR anything the backstop regex
		// catches - so backfill leaves nothing the normal ingest path would
		// strip. Guard on `changed` so already-clean configs are not rewritten.
		// Re-storing via Upsert (same sha + non-"write" source) replaces the
		// canonical content with the blanked form and appends no history row.
		if _, changed, berr := blankConfigSecrets(snap.Content); berr == nil && changed {
			if err := files.Upsert(ctx, d.TenantID, d.ID, "config.json", snap.Content, snap.SHA256, "backfill", nil); err != nil {
				return res, fmt.Errorf("backfill: reblank config %s/%s: %w", d.TenantID, d.DeviceID, err)
			}
			slog.Info("backfill: migrated + blanked device config",
				"tenant", d.TenantID, "device", d.DeviceID, "fields", len(found))
		}
	}
	return res, nil
}
