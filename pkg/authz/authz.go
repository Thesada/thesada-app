// Package authz is the single decision point for privileged actions.
// Handlers ask Can/Require with a typed Action instead of reading
// user.IsSuperAdmin inline, so the grant model has one place to change
// (e.g. a future role system) and privileged surfaces stay greppable
// by Action name. Route-level gating stays in authmw (RequireSuperAdmin
// wraps the /admin tree); this package covers the per-action checks
// inside handlers that serve both tenant users and operators.
//
// Deliberately DB-free: a decision is a pure function of the resolved
// user and the action. The service-layer SQL guards (e.g. the guarded
// UPDATE in AuthService.SetImpersonation) stay as defence in depth.
package authz

import (
	"errors"
	"fmt"

	"thesada.app/app/pkg/service"
)

// Action names one privileged operation. Values are dotted slugs and
// double as the `action` column in the admin_audit table, so the authz
// vocabulary and the audit trail stay one taxonomy.
type Action string

// Cross-tenant actions surfaced by handlers that serve both tenant users
// and operators (the former inline IsSuperAdmin checks).
const (
	// DeviceReadCrossTenant reads a device outside the caller's effective tenant.
	DeviceReadCrossTenant Action = "device.read_cross_tenant"
	// SensorDeleteCrossTenant deletes sensor telemetry on a cross-tenant device.
	SensorDeleteCrossTenant Action = "sensor.delete_cross_tenant"
	// MQTTPublishAnyTenant publishes to any tenant's MQTT topic tree.
	MQTTPublishAnyTenant Action = "mqtt.publish_any_tenant"
)

// Privileged admin mutations. Each successful mutation records an
// admin_audit row whose action is the Action value below.
const (
	ImpersonationSet      Action = "impersonation.set"
	ImpersonationClear    Action = "impersonation.clear"
	WaitlistConvert       Action = "waitlist.convert"
	WaitlistDelete        Action = "waitlist.delete"
	CertIssue             Action = "cert.issue"
	CertRevoke            Action = "cert.revoke"
	DeviceDelete          Action = "device.delete"
	DeviceReassign        Action = "device.reassign"
	DeviceSecretSet       Action = "device_secret.set"
	DeviceSecretProvision Action = "device_secret.provision"
	OTADispatch           Action = "ota.dispatch"
	MQTTShellPublish      Action = "mqtt.shell_publish"
)

// ErrForbidden is returned by Require when the user may not perform the
// action. Callers translate it to their transport's denial (404 cloak on
// the web tree, 403 on the JSON API).
var ErrForbidden = errors.New("authz: forbidden")

// superAdminActions is the full grant table: today every known action is
// granted by the users.is_super_admin flag and nothing else. An action
// missing from this map is denied for everyone, so a typo'd or unregistered
// Action fails closed.
var superAdminActions = map[Action]bool{
	DeviceReadCrossTenant:   true,
	SensorDeleteCrossTenant: true,
	MQTTPublishAnyTenant:    true,
	ImpersonationSet:        true,
	ImpersonationClear:      true,
	WaitlistConvert:         true,
	WaitlistDelete:          true,
	CertIssue:               true,
	CertRevoke:              true,
	DeviceDelete:            true,
	DeviceReassign:          true,
	DeviceSecretSet:         true,
	DeviceSecretProvision:   true,
	OTADispatch:             true,
	MQTTShellPublish:        true,
}

// Can reports whether u may perform a. Nil-safe: an anonymous caller can
// do nothing, and an unknown action is denied for everyone.
// in: resolved user (nil = anonymous), action. out: allowed.
func Can(u *service.User, a Action) bool {
	if u == nil {
		return false
	}
	return superAdminActions[a] && u.IsSuperAdmin
}

// Require is Can as an error: nil when allowed, ErrForbidden (wrapped with
// the action for logs) when not.
// in: resolved user (nil = anonymous), action. out: nil or ErrForbidden.
func Require(u *service.User, a Action) error {
	if Can(u, a) {
		return nil
	}
	return fmt.Errorf("%w: %s", ErrForbidden, a)
}
