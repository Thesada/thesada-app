// secret.go - SecretService: the storage + retrieval layer for
// device-config secrets (#443, phase 2). It sits on top of the pure
// envelope-crypto core in pkg/secrets and the two tables from
// migration 0023 (tenant_dek, device_config_secrets).
//
// Key hierarchy (see pkg/secrets):
//
//	root KEK (THESADA_DEVICE_CONFIG_KEK) -> per-tenant DEK -> secret value
//
// The operator writes secrets (SetSecret) and reads only set/unset status
// (Status); the value never comes back out to the UI. The server can
// decrypt (Reveal) to provision a device at pair time (phase 5) - that path
// is server-side only, never wired to an operator-facing handler.
//
// Feature gate: an empty THESADA_DEVICE_CONFIG_KEK leaves keyring nil and
// every write/decrypt path returns ErrSecretsDisabled; devices keep their
// plaintext config. A malformed KEK is a hard construction error at boot
// (NewSecretService), not a silent fallback.
package service

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/secrets"
)

// SecretFields is the closed set of device-config fields that are stored
// encrypted. It mirrors the CHECK constraint in migration 0023 and, by
// design decision, the firmware secret.set field keys (#442
// secret_keymap.h) so provisioning maps them cleanly to device NVS. Order
// is the display order.
//
// Four map 1:1 to the firmware secret.set field. The exception is
// wifi.password: the firmware keys wifi passwords per-SSID
// ("wifi.password:<ssid>"), so provisioning appends the device's configured
// SSID (see FirmwareSecretField). The app stores a single wifi.password per
// device; the SSID is resolved at provision time from the device config.
var SecretFields = []string{
	"wifi.password",
	"mqtt.password",
	"telegram.bot_token",
	"web.password",
	"wifi.ap_password",
}

// FirmwareSecretField maps an app storage field key (a SecretFields entry) to
// the firmware secret.set field key (#442 secret_keymap.h). All but
// wifi.password are identical. wifi.password is per-SSID on the firmware, so
// it becomes "wifi.password:<ssid>" and needs the device's configured SSID;
// ok is false when the SSID is unknown, so the caller skips it rather than
// pushing a field the firmware rejects ("unknown field or NVS write failed").
// in: storage field, device wifi SSID (may be ""). out: firmware field, ok.
func FirmwareSecretField(field, ssid string) (string, bool) {
	if field == "wifi.password" {
		if ssid == "" {
			return "", false
		}
		return "wifi.password:" + ssid, true
	}
	return field, true
}

// ErrSecretsDisabled is returned by every write/decrypt path when the
// feature is off (THESADA_DEVICE_CONFIG_KEK unset). Status stays available
// because it only reads existence, not values.
var ErrSecretsDisabled = errors.New("secret: device-config secrets disabled (THESADA_DEVICE_CONFIG_KEK unset)")

// SecretService encrypts, stores, and (server-side) decrypts device-config
// secrets. keyring holds the deployment root KEK; nil means the feature is
// off.
type SecretService struct {
	cfg     *config.Config
	pools   db.Pools
	keyring *secrets.Keyring
}

// NewSecretService builds the service and its keyring. Empty KEK -> feature
// off (keyring nil, no error). Non-empty but malformed KEK -> error, so a
// mis-set env var fails the boot loudly instead of silently disabling the
// feature.
// in: cfg, pools. out: *SecretService, error.
func NewSecretService(cfg *config.Config, pools db.Pools) (*SecretService, error) {
	s := &SecretService{cfg: cfg, pools: pools}
	if cfg.DeviceConfigKEK == "" {
		return s, nil
	}
	kr, err := secrets.NewKeyring(cfg.DeviceConfigKEK)
	if err != nil {
		return nil, fmt.Errorf("secret service: %w", err)
	}
	s.keyring = kr
	return s, nil
}

// Enabled reports whether the feature is on (root KEK configured). Callers
// gate UI + provisioning on this.
func (s *SecretService) Enabled() bool { return s.keyring != nil }

// EnsureTenantDEK creates the tenant's wrapped DEK if it does not exist yet,
// idempotently, on its own App-pool transaction. Used for backfill (phase 7)
// and any caller that has no tx in hand; tenant-create provisions the DEK in
// its own tx via ensureTenantDEKTx. The write paths below also create lazily,
// so tenants that predate the feature still work.
// in: ctx, tenant_id. out: error.
func (s *SecretService) EnsureTenantDEK(ctx context.Context, tenantID string) error {
	if s.keyring == nil {
		return ErrSecretsDisabled
	}
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return s.ensureTenantDEKTx(ctx, tx, tenantID)
	})
}

// ensureTenantDEKTx inserts a fresh wrapped DEK for the tenant if none exists,
// within an already-open tx. Idempotent via ON CONFLICT DO NOTHING, so a
// concurrent creator (or a re-run) is a harmless no-op. The caller supplies
// the tx and its pool/RLS context: tenant-create passes its admin (BYPASSRLS)
// tx so tenant + DEK land atomically; EnsureTenantDEK passes an App-pool tx
// with app.tenant_id set. Caller must have checked keyring != nil.
// in: ctx, tx, tenant_id. out: error.
func (s *SecretService) ensureTenantDEKTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	dek, err := s.keyring.GenerateDEK()
	if err != nil {
		return err
	}
	wrapped, err := s.keyring.WrapDEK(dek, dekAAD(tenantID))
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO tenant_dek (tenant_id, wrapped_dek) VALUES ($1, $2)
		 ON CONFLICT (tenant_id) DO NOTHING`, tenantID, wrapped)
	return err
}

// ProvisionTenantDEKTx is the exported entry tenant-create uses to seal a DEK
// in the SAME transaction as the tenants INSERT. No-op (nil) when the feature
// is off, so callers do not have to branch on Enabled().
// in: ctx, open tx, tenant_id. out: error.
func (s *SecretService) ProvisionTenantDEKTx(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if s.keyring == nil {
		return nil
	}
	return s.ensureTenantDEKTx(ctx, tx, tenantID)
}

// SetSecret encrypts value under the tenant DEK and upserts it for
// (tenant, device, field), overwriting any prior value. Device-level only in
// v1; tenant-default secrets (device_pk NULL) are #450.
// in: ctx, tenant_id, device pk, field, plaintext value. out: error.
func (s *SecretService) SetSecret(ctx context.Context, tenantID string, devicePk uuid.UUID, field, value string) error {
	if s.keyring == nil {
		return ErrSecretsDisabled
	}
	if !validSecretField(field) {
		return fmt.Errorf("secret: unknown field %q", field)
	}
	if devicePk == uuid.Nil {
		return errors.New("secret: device-level SetSecret requires a device pk (tenant-default secrets are #450)")
	}
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		dek, err := s.tenantDEK(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		blob, err := secrets.EncryptSecret(dek, []byte(value), secretAAD(tenantID, devicePk, field))
		if err != nil {
			return fmt.Errorf("secret: encrypt %s: %w", field, err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO device_config_secrets (tenant_id, device_pk, field, ciphertext)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT (device_pk, field) WHERE device_pk IS NOT NULL
			DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_at = now()`,
			tenantID, devicePk, field, blob)
		return err
	})
}

// Status reports which fields are set for a device, never the values. Every
// known field is present in the map; unset fields map to false. Works with
// the feature off (pure existence read, no decrypt).
// in: ctx, tenant_id, device pk. out: field -> isSet, error.
func (s *SecretService) Status(ctx context.Context, tenantID string, devicePk uuid.UUID) (map[string]bool, error) {
	out := make(map[string]bool, len(SecretFields))
	for _, f := range SecretFields {
		out[f] = false
	}
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT field FROM device_config_secrets WHERE device_pk = $1`, devicePk)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f string
			if err := rows.Scan(&f); err != nil {
				return err
			}
			out[f] = true
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Reveal decrypts a single stored secret. SERVER-SIDE ONLY: used by
// provision-at-pair (phase 5) and rotation (phase 7), never wired to an
// operator-facing route - the operator write-only contract depends on this
// method staying off the request surface. Returns found=false (no error)
// when the field is unset.
// in: ctx, tenant_id, device pk, field. out: plaintext, found, error.
func (s *SecretService) Reveal(ctx context.Context, tenantID string, devicePk uuid.UUID, field string) (string, bool, error) {
	if s.keyring == nil {
		return "", false, ErrSecretsDisabled
	}
	if !validSecretField(field) {
		return "", false, fmt.Errorf("secret: unknown field %q", field)
	}
	var value string
	found := false
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		var blob []byte
		scanErr := tx.QueryRow(ctx,
			`SELECT ciphertext FROM device_config_secrets WHERE device_pk = $1 AND field = $2`,
			devicePk, field).Scan(&blob)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			return nil
		}
		if scanErr != nil {
			return scanErr
		}
		dek, err := s.tenantDEK(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		pt, err := secrets.DecryptSecret(dek, blob, secretAAD(tenantID, devicePk, field))
		if err != nil {
			return fmt.Errorf("secret: decrypt %s: %w", field, err)
		}
		value = string(pt)
		found = true
		return nil
	})
	if err != nil {
		return "", false, err
	}
	return value, found, nil
}

// RotationResult reports what a RotateRootKEK sweep did. Rotated rows were
// re-wrapped old -> new; AlreadyNew rows were already under the new key and
// left untouched. The operator re-runs until Rotated == 0.
type RotationResult struct {
	Rotated    int
	AlreadyNew int
}

// RotateRootKEK re-wraps every tenant DEK under newKeyring: unwrap each
// wrapped_dek under the current root KEK (s.keyring, the OLD key), re-wrap it
// under newKeyring, and UPDATE the row (bumping kek_version). The DEK itself
// is unchanged, so device_config_secrets ciphertext is NOT touched and the
// AAD (tenant_id) is identical for unwrap and re-wrap - only the KEK changes.
// The whole sweep runs in one admin (BYPASSRLS) tx so it is atomic.
//
// Tolerant + idempotent: a row that will not unwrap under the old key is
// retried under the NEW key; if that succeeds the row is already rotated and
// is skipped (counted in AlreadyNew), not double-wrapped. A row that unwraps
// under NEITHER is a genuine key mismatch and fails the whole tx. This makes
// the sweep safe to re-run, which is how the swap-window race is closed: a DEK
// minted (under the old key) after an earlier sweep is picked up by the next
// run instead of being orphaned.
//
// Operator flow: keep THESADA_DEVICE_CONFIG_KEK on the live (old) key so the
// running app still unwraps and mints new DEKs under it, set
// THESADA_DEVICE_CONFIG_KEK_NEW, run `rotate-kek` REPEATEDLY until it reports
// 0 rotated, then swap the live key to the new one and restart promptly.
// in: ctx, new keyring. out: rotation counts, error.
func (s *SecretService) RotateRootKEK(ctx context.Context, newKeyring *secrets.Keyring) (RotationResult, error) {
	var res RotationResult
	if s.keyring == nil {
		return res, ErrSecretsDisabled
	}
	if newKeyring == nil {
		return res, errors.New("secret: rotate requires a new keyring")
	}
	err := db.WithAdminAudit(ctx, s.pools.Admin, "secret.rotate_root_kek", func(tx pgx.Tx) error {
		// Collect first: a single connection cannot iterate a cursor while also
		// running the per-row UPDATE.
		type dekRow struct {
			tenant  string
			wrapped []byte
		}
		var all []dekRow
		rows, err := tx.Query(ctx, `SELECT tenant_id, wrapped_dek FROM tenant_dek`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var rr dekRow
			if err := rows.Scan(&rr.tenant, &rr.wrapped); err != nil {
				rows.Close()
				return err
			}
			all = append(all, rr)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}

		for _, rr := range all {
			dek, err := s.keyring.UnwrapDEK(rr.wrapped, dekAAD(rr.tenant))
			if err != nil {
				// Not under the old key - maybe already rotated. If it unwraps
				// under the new key, skip it; otherwise it is a real mismatch.
				if _, newErr := newKeyring.UnwrapDEK(rr.wrapped, dekAAD(rr.tenant)); newErr == nil {
					res.AlreadyNew++
					continue
				}
				return fmt.Errorf("secret: DEK for %q unwraps under neither the current nor the new KEK", rr.tenant)
			}
			rewrapped, err := newKeyring.WrapDEK(dek, dekAAD(rr.tenant))
			if err != nil {
				return fmt.Errorf("secret: rewrap DEK for %q: %w", rr.tenant, err)
			}
			if _, err := tx.Exec(ctx,
				`UPDATE tenant_dek SET wrapped_dek = $1, kek_version = kek_version + 1, updated_at = now()
				 WHERE tenant_id = $2`, rewrapped, rr.tenant); err != nil {
				return err
			}
			res.Rotated++
		}
		return nil
	})
	if err != nil {
		return RotationResult{}, err
	}
	return res, nil
}

// tenantDEK returns the tenant's unwrapped DEK within an open tx, creating
// and persisting a fresh wrapped DEK on first use. Race-safe: the INSERT ...
// ON CONFLICT DO NOTHING plus a re-read means a losing concurrent creator
// adopts the winner's DEK instead of its own. Caller holds the App-pool tx
// with app.tenant_id set (RLS scopes tenant_dek to this tenant).
// in: ctx, tx, tenant_id. out: 32-byte DEK, error.
func (s *SecretService) tenantDEK(ctx context.Context, tx pgx.Tx, tenantID string) ([]byte, error) {
	var wrapped []byte
	err := tx.QueryRow(ctx,
		`SELECT wrapped_dek FROM tenant_dek WHERE tenant_id = $1`, tenantID).Scan(&wrapped)
	if errors.Is(err, pgx.ErrNoRows) {
		if cerr := s.ensureTenantDEKTx(ctx, tx, tenantID); cerr != nil {
			return nil, cerr
		}
		// Re-read: on conflict our INSERT was a no-op, so use the persisted
		// (possibly another tx's) wrapped DEK, never the local one we minted.
		if rerr := tx.QueryRow(ctx,
			`SELECT wrapped_dek FROM tenant_dek WHERE tenant_id = $1`, tenantID).Scan(&wrapped); rerr != nil {
			return nil, rerr
		}
	} else if err != nil {
		return nil, err
	}
	return s.keyring.UnwrapDEK(wrapped, dekAAD(tenantID))
}

// dekAAD binds a wrapped DEK to its owning tenant.
func dekAAD(tenantID string) []byte { return []byte(tenantID) }

// secretAAD binds a secret ciphertext to its tenant/device/field identity so
// a DB-write attacker cannot relocate one row's ciphertext onto another.
func secretAAD(tenantID string, devicePk uuid.UUID, field string) []byte {
	return []byte(tenantID + "\x00" + devicePk.String() + "\x00" + field)
}

// validSecretField reports whether field is one of the known encrypted
// fields (mirrors the CHECK in migration 0023).
func validSecretField(field string) bool {
	for _, f := range SecretFields {
		if f == field {
			return true
		}
	}
	return false
}
