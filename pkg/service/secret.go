// secret.go - SecretService: the storage + retrieval layer for
// device-config secrets. It sits on top of the pure envelope-crypto core in
// pkg/secrets and the two tables tenant_dek + device_config_secrets.
//
// Key hierarchy (see pkg/secrets):
//
//	root KEK (THESADA_DEVICE_CONFIG_KEK) -> per-tenant DEK -> secret value
//
// The operator writes secrets (SetSecret) and reads only set/unset status
// (Status); the value never comes back out to the UI. The server can
// decrypt (Reveal) to provision a device at pair time - that path is
// server-side only, never wired to an operator-facing handler.
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
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/secrets"
)

// WifiPasswordPrefix keys a per-SSID WiFi password. The firmware stores each
// network's password in NVS under "wifi.password:<ssid>"; the app stores one
// row per network under the same key, so storage field == firmware field.
const WifiPasswordPrefix = "wifi.password:"

// LegacyWifiPassword is the bare storage field from before per-SSID support.
// It carries no SSID, so provisioning appends the device's primary configured
// SSID; new writes always use the per-SSID form.
const LegacyWifiPassword = "wifi.password"

// ScalarSecretFields is the closed set of non-WiFi device-config secrets, each
// mapping 1:1 to a firmware secret.set field. Order is display order; per-SSID
// WiFi passwords are appended after these, one per configured network.
var ScalarSecretFields = []string{
	"mqtt.password",
	"telegram.bot_token",
	"web.password",
	"wifi.ap_password",
}

// WifiSecretField builds the per-SSID storage/firmware field for a network
// password. out: "" for an empty SSID so callers skip it.
func WifiSecretField(ssid string) string {
	if ssid == "" {
		return ""
	}
	return WifiPasswordPrefix + ssid
}

// IsWifiPasswordField reports whether field is a per-SSID WiFi password
// ("wifi.password:<ssid>") or the legacy bare "wifi.password".
func IsWifiPasswordField(field string) bool {
	return field == LegacyWifiPassword ||
		(strings.HasPrefix(field, WifiPasswordPrefix) && len(field) > len(WifiPasswordPrefix))
}

// FirmwareSecretField maps a storage field to the firmware secret.set field.
// Scalars and per-SSID WiFi keys are identical; the legacy bare wifi.password
// is the only remap, needing a device SSID appended (ok=false when none known,
// so the caller skips it).
// in: storage field, device primary SSID (legacy field only). out: firmware field, ok.
func FirmwareSecretField(field, primarySSID string) (string, bool) {
	if field == LegacyWifiPassword {
		if primarySSID == "" {
			return "", false
		}
		return WifiPasswordPrefix + primarySSID, true
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
// (tenant, device, field), overwriting any prior value. A device row always
// wins over the tenant default for that field (see Resolve); use
// SetTenantSecret for the default itself.
// in: ctx, tenant_id, device pk, field, plaintext value. out: error.
func (s *SecretService) SetSecret(ctx context.Context, tenantID string, devicePk uuid.UUID, field, value string) error {
	if s.keyring == nil {
		return ErrSecretsDisabled
	}
	if !validSecretField(field) {
		return fmt.Errorf("secret: unknown field %q", field)
	}
	if devicePk == uuid.Nil {
		return errors.New("secret: device-level SetSecret requires a device pk (use SetTenantSecret for tenant defaults)")
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

// SetTenantSecret stores the tenant-wide default for field: the value every
// device in the tenant resolves to unless it carries its own override. Written
// as a device_pk IS NULL row, so the conflict target is the partial unique
// index on (tenant_id, field) rather than the device one.
// Rotating a default is just an overwrite here; pushing it to devices is the
// caller's fan-out (see ProvisionTargets).
// in: ctx, tenant_id, field, plaintext value. out: error.
func (s *SecretService) SetTenantSecret(ctx context.Context, tenantID, field, value string) error {
	if s.keyring == nil {
		return ErrSecretsDisabled
	}
	if !validSecretField(field) {
		return fmt.Errorf("secret: unknown field %q", field)
	}
	// The legacy bare key carries no SSID, so provisioning appends the DEVICE's
	// primary SSID (FirmwareSecretField). At tenant level there is no device to
	// borrow one from, and the remap would land on wifi.password:<ssid> - the
	// same NVS key a device's own per-SSID override writes, letting a default
	// clobber an override. Reject it: a tenant default must name its network.
	if field == LegacyWifiPassword {
		return fmt.Errorf("secret: %q is device-level only; a tenant default must name its network (%s<ssid>)",
			LegacyWifiPassword, WifiPasswordPrefix)
	}
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		dek, err := s.tenantDEK(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		blob, err := secrets.EncryptSecret(dek, []byte(value), tenantSecretAAD(tenantID, field))
		if err != nil {
			return fmt.Errorf("secret: encrypt tenant default %s: %w", field, err)
		}
		_, err = tx.Exec(ctx, `
			INSERT INTO device_config_secrets (tenant_id, device_pk, field, ciphertext)
			VALUES ($1, NULL, $2, $3)
			ON CONFLICT (tenant_id, field) WHERE device_pk IS NULL
			DO UPDATE SET ciphertext = EXCLUDED.ciphertext, updated_at = now()`,
			tenantID, field, blob)
		return err
	})
}

// ClearDeviceSecret deletes a device's override for field so the device falls
// back to the tenant default. Deleting an absent row is a no-op (found=false),
// not an error - the operator's intent is "no override here" either way.
// The device NVS still holds the old value until it is re-provisioned.
// in: ctx, tenant_id, device pk, field. out: deleted, error.
func (s *SecretService) ClearDeviceSecret(ctx context.Context, tenantID string, devicePk uuid.UUID, field string) (bool, error) {
	if devicePk == uuid.Nil {
		return false, errors.New("secret: ClearDeviceSecret requires a device pk")
	}
	if !validSecretField(field) {
		return false, fmt.Errorf("secret: unknown field %q", field)
	}
	deleted := false
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM device_config_secrets WHERE device_pk = $1 AND field = $2`,
			devicePk, field)
		if err != nil {
			return err
		}
		deleted = tag.RowsAffected() > 0
		return nil
	})
	if err != nil {
		return false, err
	}
	return deleted, nil
}

// ClearTenantSecret deletes the tenant default for field. Devices with an
// override keep it; devices without one resolve to nothing afterwards.
// in: ctx, tenant_id, field. out: deleted, error.
func (s *SecretService) ClearTenantSecret(ctx context.Context, tenantID, field string) (bool, error) {
	if !validSecretField(field) {
		return false, fmt.Errorf("secret: unknown field %q", field)
	}
	deleted := false
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx,
			`DELETE FROM device_config_secrets WHERE device_pk IS NULL AND field = $1`, field)
		if err != nil {
			return err
		}
		deleted = tag.RowsAffected() > 0
		return nil
	})
	if err != nil {
		return false, err
	}
	return deleted, nil
}

// Status reports which fields are set for a device, never the values. The 4
// scalar fields are always present (unset -> false); every stored per-SSID
// WiFi password (and any legacy bare wifi.password) is added as true. Works
// with the feature off (pure existence read, no decrypt).
// in: ctx, tenant_id, device pk. out: field -> isSet, error.
func (s *SecretService) Status(ctx context.Context, tenantID string, devicePk uuid.UUID) (map[string]bool, error) {
	out := make(map[string]bool, len(ScalarSecretFields)+2)
	for _, f := range ScalarSecretFields {
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

// SecretOrigin says where a resolved value came from, or that there is none.
type SecretOrigin string

const (
	// OriginUnset - neither a device override nor a tenant default exists.
	OriginUnset SecretOrigin = "unset"
	// OriginOverride - the device carries its own value, shadowing any default.
	OriginOverride SecretOrigin = "override"
	// OriginTenant - the value is inherited from the tenant default.
	OriginTenant SecretOrigin = "tenant"
)

// Resolve returns the effective secret for a device: its own override if it
// has one, otherwise the tenant default. This is the provisioning read - use
// it wherever a value is about to be pushed to a device. Reveal stays the
// exact-row read and does NOT fall back, so callers that mean "this device's
// own value" keep getting exactly that.
//
// SERVER-SIDE ONLY, same contract as Reveal: never wire it to an
// operator-facing route, or the write-only guarantee is gone.
// in: ctx, tenant_id, device pk, field. out: plaintext, origin, error.
func (s *SecretService) Resolve(ctx context.Context, tenantID string, devicePk uuid.UUID, field string) (string, SecretOrigin, error) {
	if s.keyring == nil {
		return "", OriginUnset, ErrSecretsDisabled
	}
	if !validSecretField(field) {
		return "", OriginUnset, fmt.Errorf("secret: unknown field %q", field)
	}
	value := ""
	origin := OriginUnset
	// The legacy bare key is device-level only: it carries no SSID, so a
	// tenant-level row under it would provision onto some device's primary
	// SSID. SetTenantSecret refuses to create one; this refuses to read one,
	// so a row planted by an older build or by direct SQL stays inert.
	deviceOnly := field == LegacyWifiPassword
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		// One round trip, device row first. ORDER BY puts the override ahead of
		// the default so LIMIT 1 is the precedence rule, in SQL rather than in
		// two queries that could interleave with a concurrent write.
		var blob []byte
		var isDevice bool
		scanErr := tx.QueryRow(ctx, `
			SELECT ciphertext, device_pk IS NOT NULL
			  FROM device_config_secrets
			 WHERE field = $2
			   AND (device_pk = $1 OR (device_pk IS NULL AND NOT $3))
			 ORDER BY device_pk IS NULL
			 LIMIT 1`, devicePk, field, deviceOnly).Scan(&blob, &isDevice)
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
		aad := tenantSecretAAD(tenantID, field)
		if isDevice {
			aad = secretAAD(tenantID, devicePk, field)
		}
		pt, err := secrets.DecryptSecret(dek, blob, aad)
		if err != nil {
			return fmt.Errorf("secret: decrypt %s: %w", field, err)
		}
		value = string(pt)
		origin = OriginTenant
		if isDevice {
			origin = OriginOverride
		}
		return nil
	})
	if err != nil {
		return "", OriginUnset, err
	}
	return value, origin, nil
}

// RevealTenantSecret decrypts a tenant default. Server-side only, same
// contract as Reveal. Returns found=false (no error) when unset.
// in: ctx, tenant_id, field. out: plaintext, found, error.
func (s *SecretService) RevealTenantSecret(ctx context.Context, tenantID, field string) (string, bool, error) {
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
			`SELECT ciphertext FROM device_config_secrets WHERE device_pk IS NULL AND field = $1`,
			field).Scan(&blob)
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
		pt, err := secrets.DecryptSecret(dek, blob, tenantSecretAAD(tenantID, field))
		if err != nil {
			return fmt.Errorf("secret: decrypt tenant default %s: %w", field, err)
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

// TenantStatus reports which tenant defaults are set, never the values. Same
// shape and contract as Status: the 4 scalars are always present, stored WiFi
// rows are added as true. Works with the feature off.
// in: ctx, tenant_id. out: field -> isSet, error.
func (s *SecretService) TenantStatus(ctx context.Context, tenantID string) (map[string]bool, error) {
	out := make(map[string]bool, len(ScalarSecretFields)+2)
	for _, f := range ScalarSecretFields {
		out[f] = false
	}
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT field FROM device_config_secrets WHERE device_pk IS NULL`)
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

// OriginStatus reports, per field, whether the device is on its own override,
// inheriting the tenant default, or has neither. Existence read only, no
// decrypt, so it works with the feature off - the UI needs it to render the
// override/inherited badge without ever touching a value.
// in: ctx, tenant_id, device pk. out: field -> origin, error.
func (s *SecretService) OriginStatus(ctx context.Context, tenantID string, devicePk uuid.UUID) (map[string]SecretOrigin, error) {
	out := make(map[string]SecretOrigin, len(ScalarSecretFields)+2)
	for _, f := range ScalarSecretFields {
		out[f] = OriginUnset
	}
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT field, device_pk IS NOT NULL
			  FROM device_config_secrets
			 WHERE device_pk = $1 OR device_pk IS NULL`, devicePk)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f string
			var isDevice bool
			if err := rows.Scan(&f, &isDevice); err != nil {
				return err
			}
			// A device row wins whatever order the rows arrive in.
			if isDevice {
				out[f] = OriginOverride
			} else if out[f] != OriginOverride {
				out[f] = OriginTenant
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ProvisionTargets lists the devices a tenant-default change must reach: every
// paired device in the tenant that does NOT carry its own override for field.
// An overridden device is deliberately absent - rotating a default must not
// disturb a device the operator has pinned.
//
// A pre-per-SSID device row (bare "wifi.password", still valid per migration
// 0024) provisions onto wifi.password:<primary SSID>, the same NVS key a
// per-SSID default writes. It counts as an override for any per-SSID WiFi
// field, conservatively: skipping a device that may not have needed skipping
// costs a re-provision, clobbering a pinned WiFi password costs the network.
//
// Devices that have never paired are excluded: there is no NVS to write and no
// topic to reach them on, and pairing provisions from the store anyway.
// in: ctx, tenant_id, field. out: device pks, error.
func (s *SecretService) ProvisionTargets(ctx context.Context, tenantID, field string) ([]uuid.UUID, error) {
	if !validSecretField(field) {
		return nil, fmt.Errorf("secret: unknown field %q", field)
	}
	var out []uuid.UUID
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT d.id
			  FROM devices d
			 WHERE d.tenant_id = $1
			   AND d.paired_at IS NOT NULL
			   AND NOT EXISTS (
			       SELECT 1 FROM device_config_secrets s
			        WHERE s.device_pk = d.id
			          AND (s.field = $2
			               OR ($2 LIKE $3 AND s.field = $4)))
			 ORDER BY d.last_seen_at DESC NULLS LAST`,
			tenantID, field, WifiPasswordPrefix+"%", LegacyWifiPassword)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id uuid.UUID
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ProvisionTargetCounts returns, per field, how many devices a default change
// would have to reach. One query for the whole page: the per-field variant ran
// its own transaction each time, which is a round trip per row rendered.
// in: ctx, tenant_id. out: field -> inheritor count, error.
func (s *SecretService) ProvisionTargetCounts(ctx context.Context, tenantID string) (map[string]int, error) {
	out := map[string]int{}
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT t.field, count(d.id)
			  FROM device_config_secrets t
			  LEFT JOIN devices d
			    ON d.tenant_id = $1
			   AND d.paired_at IS NOT NULL
			   AND NOT EXISTS (
			       SELECT 1 FROM device_config_secrets o
			        WHERE o.device_pk = d.id
			          AND (o.field = t.field
			               OR (t.field LIKE $2 AND o.field = $3)))
			 WHERE t.device_pk IS NULL
			 GROUP BY t.field`, tenantID, WifiPasswordPrefix+"%", LegacyWifiPassword)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f string
			var n int
			if err := rows.Scan(&f, &n); err != nil {
				return err
			}
			out[f] = n
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
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

// tenantDefaultMarker stands in for the device pk in a tenant-default AAD. It
// is not a UUID, so it can never collide with a real device's AAD however the
// uuid package chooses to format the nil value.
const tenantDefaultMarker = "tenant-default"

// tenantSecretAAD binds a tenant-default ciphertext to its tenant/field. Same
// role as secretAAD: a default's ciphertext must not open as a device row's,
// and vice versa.
func tenantSecretAAD(tenantID, field string) []byte {
	return []byte(tenantID + "\x00" + tenantDefaultMarker + "\x00" + field)
}

// validSecretField reports whether field is a storable encrypted secret:
// one of the 4 scalars, a per-SSID WiFi password ("wifi.password:<ssid>"),
// or the legacy bare "wifi.password". Mirrors the CHECK in migration 0024.
func validSecretField(field string) bool {
	for _, f := range ScalarSecretFields {
		if f == field {
			return true
		}
	}
	return IsWifiPasswordField(field)
}
