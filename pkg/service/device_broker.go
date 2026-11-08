// Broker identity bookkeeping. A device's dynsec client, role and cert CN are
// named after the tenant they were issued under, which a reassign does not
// change. devices.broker_tenant_id records that tenant, and
// broker_stale_tenants the older identities still to be torn down (0040).
package service

import (
	"context"
	"errors"
	"log/slog"
	"slices"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"thesada.app/app/pkg/db"
)

// ErrBrokerIdentityTaken means another device row holds the broker identity
// this tenant and device_id would be issued, typically the unit after a reassign.
var ErrBrokerIdentityTaken = errors.New("device: broker identity held by another device row")

// BrokerIdentity is what a device row holds on the broker.
type BrokerIdentity struct {
	DevicePk uuid.UUID
	Current  string   // tenant of the live identity, "" for none
	Stale    []string // tenants of older identities a teardown still deletes
}

// Tenants lists every identity to delete, current first.
// in: none. out: tenants, without duplicates or empties.
func (b BrokerIdentity) Tenants() []string {
	out := make([]string, 0, 1+len(b.Stale))
	for _, t := range append([]string{b.Current}, b.Stale...) {
		if t != "" && !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	return out
}

// violates reports whether err is a unique violation of the named index.
// in: error, index name. out: bool.
func violates(err error, index string) bool {
	var pg *pgconn.PgError
	return errors.As(err, &pg) && pg.Code == "23505" && pg.ConstraintName == index
}

// identityHeldElsewhere is true when a row other than $3 holds tenant $1's
// identity for device_id $2, live or still awaiting teardown.
const identityHeldElsewhere = `EXISTS (SELECT 1 FROM devices o
	WHERE o.device_id = $2 AND o.id <> $3
	  AND (o.broker_tenant_id = $1 OR $1 = ANY(o.broker_stale_tenants)))`

// ReserveBrokerIdentity records that the device row (tenantID, deviceID)
// holds the broker identity issued under tenantID. A different identity it
// held moves to the stale list, so it stays recorded until its teardown
// succeeds. Call it before any broker write. Cross-tenant by design.
// in: ctx, tenant, device id. out: the identity after the reservation,
// error (ErrBrokerIdentityTaken, pgx.ErrNoRows when the row does not exist).
func (s *DeviceService) ReserveBrokerIdentity(ctx context.Context, tenantID, deviceID string) (BrokerIdentity, error) {
	var out BrokerIdentity
	err := db.WithAdminAudit(ctx, s.pools.Admin, "device broker identity reserve", func(tx pgx.Tx) error {
		var err error
		out, err = reserveBrokerIdentityTx(ctx, tx, tenantID, deviceID)
		return err
	})
	return out, err
}

// reserveBrokerIdentityTx is ReserveBrokerIdentity inside the caller's
// transaction. A taken identity returns before any write.
// in: ctx, tx, tenant, device id. out: identity, error.
func reserveBrokerIdentityTx(ctx context.Context, tx pgx.Tx, tenantID, deviceID string) (BrokerIdentity, error) {
	var out BrokerIdentity
	var prev *string
	var stale []string
	if err := tx.QueryRow(ctx,
		`SELECT id, broker_tenant_id, broker_stale_tenants FROM devices
		  WHERE tenant_id = $1 AND device_id = $2 FOR UPDATE`,
		tenantID, deviceID).Scan(&out.DevicePk, &prev, &stale); err != nil {
		return out, err
	}
	var taken bool
	if err := tx.QueryRow(ctx, `SELECT `+identityHeldElsewhere,
		tenantID, deviceID, out.DevicePk).Scan(&taken); err != nil {
		return out, err
	}
	if taken {
		return out, ErrBrokerIdentityTaken
	}
	if prev != nil && *prev != tenantID && !slices.Contains(stale, *prev) {
		stale = append(stale, *prev)
	}
	stale = slices.DeleteFunc(stale, func(t string) bool { return t == tenantID })
	_, err := tx.Exec(ctx,
		`UPDATE devices SET broker_tenant_id = $1, broker_stale_tenants = $2 WHERE id = $3`,
		tenantID, stale, out.DevicePk)
	if violates(err, "devices_broker_identity_uniq") {
		return out, ErrBrokerIdentityTaken
	}
	out.Current, out.Stale = tenantID, stale
	return out, err
}

// BrokerIdentityOf returns what the device row holds on the broker. An
// unrecorded current identity falls back to the device's own tenant, unless
// another row holds that one: then the row has none of its own.
// Cross-tenant by design, through WithAdminAudit.
// in: ctx, device. out: identity, error.
func (s *DeviceService) BrokerIdentityOf(ctx context.Context, device *Device) (BrokerIdentity, error) {
	out := BrokerIdentity{DevicePk: device.ID}
	var recorded *string
	var rowTenant string
	var heldElsewhere bool
	err := db.WithAdminAudit(ctx, s.pools.Admin, "device broker identity lookup", func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT d.broker_tenant_id, d.broker_stale_tenants, d.tenant_id,
			        EXISTS (SELECT 1 FROM devices o
			                 WHERE o.device_id = d.device_id AND o.id <> d.id
			                   AND (o.broker_tenant_id = d.tenant_id OR d.tenant_id = ANY(o.broker_stale_tenants)))
			   FROM devices d WHERE d.id = $1`, device.ID).Scan(&recorded, &out.Stale, &rowTenant, &heldElsewhere)
	})
	if err != nil {
		return BrokerIdentity{}, err
	}
	if recorded != nil {
		out.Current = *recorded
		return out, nil
	}
	// The row's own tenant, the one the ownership check above tested, not the caller's snapshot.
	slog.Warn("device.broker_identity.unpinned", "device", device.ID, "device_id", device.DeviceID,
		"tenant", rowTenant, "held_elsewhere", heldElsewhere)
	if !heldElsewhere {
		out.Current = rowTenant
	}
	return out, nil
}

// ForgetBrokerIdentity drops one identity from the row's record once its
// broker client is gone, so that tenant and device_id can be issued again.
// in: ctx, device's tenant, device pk, the identity's tenant. out: error.
func (s *DeviceService) ForgetBrokerIdentity(ctx context.Context, tenantID string, devicePk uuid.UUID, identity string) error {
	return db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx,
			`UPDATE devices
			    SET broker_tenant_id = CASE WHEN broker_tenant_id = $2 THEN NULL ELSE broker_tenant_id END,
			        broker_stale_tenants = array_remove(broker_stale_tenants, $2)
			  WHERE id = $1`, devicePk, identity)
		return err
	})
}
