// Contract tests for the authz decision point: anonymous callers can do
// nothing, tenant users (even tenant admins) hold no privileged action,
// super-admins hold every registered action, and an unregistered action
// is denied for everyone (fail closed).
package authz

import (
	"errors"
	"strings"
	"testing"

	"thesada.app/app/pkg/service"
)

// allActions mirrors the full registered Action set so the per-action
// loops below cannot silently skip a newly added constant. Keep in sync
// with the grant table; TestAuthz_GrantTableCoversEveryAction enforces it.
var allActions = []Action{
	DeviceReadCrossTenant,
	SensorDeleteCrossTenant,
	MQTTPublishAnyTenant,
	ImpersonationSet,
	ImpersonationClear,
	WaitlistConvert,
	WaitlistDelete,
	CertIssue,
	CertRevoke,
	DeviceDelete,
	DeviceReassign,
	DeviceSecretSet,
	DeviceSecretProvision,
	OTADispatch,
	MQTTShellPublish,
}

func TestAuthz_GrantTableCoversEveryAction(t *testing.T) {
	if len(superAdminActions) != len(allActions) {
		t.Errorf("grant table has %d actions, test list has %d - update both together",
			len(superAdminActions), len(allActions))
	}
	for _, a := range allActions {
		if !superAdminActions[a] {
			t.Errorf("action %q missing from the grant table", a)
		}
	}
}

func TestCan_PerUserKindPerAction(t *testing.T) {
	tenantUser := &service.User{Email: "user@example.com", TenantID: "default"}
	tenantAdmin := &service.User{Email: "admin@example.com", TenantID: "default", IsAdmin: true}
	superAdmin := &service.User{Email: "root@example.com", TenantID: "default", IsSuperAdmin: true}

	cases := []struct {
		name string
		user *service.User
		want bool
	}{
		{"nil user denied", nil, false},
		{"tenant user denied", tenantUser, false},
		{"tenant admin denied", tenantAdmin, false},
		{"super admin allowed", superAdmin, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, a := range allActions {
				if got := Can(tc.user, a); got != tc.want {
					t.Errorf("Can(%s, %q) = %v, want %v", tc.name, a, got, tc.want)
				}
			}
		})
	}
}

func TestCan_UnknownActionDeniedEvenForSuperAdmin(t *testing.T) {
	superAdmin := &service.User{Email: "root@example.com", IsSuperAdmin: true}
	if Can(superAdmin, Action("made.up_action")) {
		t.Error("unregistered action allowed for super-admin, want fail-closed deny")
	}
	if Can(superAdmin, Action("")) {
		t.Error("empty action allowed for super-admin, want fail-closed deny")
	}
}

func TestRequire_AllowedReturnsNil(t *testing.T) {
	superAdmin := &service.User{Email: "root@example.com", IsSuperAdmin: true}
	for _, a := range allActions {
		if err := Require(superAdmin, a); err != nil {
			t.Errorf("Require(super, %q) = %v, want nil", a, err)
		}
	}
}

func TestRequire_DeniedReturnsErrForbiddenNamingTheAction(t *testing.T) {
	err := Require(nil, CertIssue)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("Require(nil, cert.issue) = %v, want ErrForbidden", err)
	}
	if !strings.Contains(err.Error(), string(CertIssue)) {
		t.Errorf("denial error %q does not name the action %q", err, CertIssue)
	}
}
