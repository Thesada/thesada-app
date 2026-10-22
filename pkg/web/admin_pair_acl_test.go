package web

import (
	"context"
	"errors"
	"slices"
	"testing"

	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/service"
)

// The device ACL must follow THESADA_MQTT_TOPIC_ROOT: a hard-coded root
// grants a renamed deployment's devices read on a tree nobody publishes to.
func TestDynsecDeviceACLsFollowTopicRoot(t *testing.T) {
	cases := []struct {
		name, root, wantRead string
		broad                bool
	}{
		{"custom root, tenant read", "acme", "acme/t1/#", false},
		{"custom root, broad read", "acme", "acme/#", true},
		{"empty root falls back", "", "thesada/t1/#", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefix := service.DeviceTopicPrefix(tc.root, "t1", "d1")
			acls := dynsecDeviceACLs(tc.root, "t1", prefix, tc.broad)
			for _, want := range []mqtt.DynsecACL{
				{ACLType: "publishClientSend", Topic: prefix + "/#", Allow: true},
				{ACLType: "subscribePattern", Topic: tc.wantRead, Allow: true},
				{ACLType: "publishClientReceive", Topic: tc.wantRead, Allow: true},
			} {
				if !slices.Contains(acls, want) {
					t.Errorf("missing %+v in %+v", want, acls)
				}
			}
		})
	}
}

// A device keeps read on its own stored prefix even when that prefix predates
// a root change and so sits outside the tenant read tree.
func TestDynsecDeviceACLsReadOwnStoredPrefix(t *testing.T) {
	acls := dynsecDeviceACLs("acme", "t1", "thesada/t1/d1", false)
	for _, typ := range []string{"subscribePattern", "publishClientReceive"} {
		if !slices.Contains(acls, mqtt.DynsecACL{ACLType: typ, Topic: "thesada/t1/d1/#", Allow: true}) {
			t.Errorf("no %s on the stored prefix: %+v", typ, acls)
		}
	}
}

// fakeRoleWriter records which dynsec role command ran.
type fakeRoleWriter struct {
	createErr error
	calls     []string
	acls      []mqtt.DynsecACL
}

func (f *fakeRoleWriter) CreateDynsecRole(_ context.Context, _ string, acls []mqtt.DynsecACL) error {
	f.calls = append(f.calls, "createRole")
	return f.createErr
}

func (f *fakeRoleWriter) SetDynsecRoleACLs(_ context.Context, _ string, acls []mqtt.DynsecACL) error {
	f.calls = append(f.calls, "modifyRole")
	f.acls = acls
	return nil
}

// An existing role must get the new ACLs, not keep the ones from its first pair.
func TestEnsureDynsecRole(t *testing.T) {
	acls := []mqtt.DynsecACL{{ACLType: "subscribePattern", Topic: "acme/t1/#", Allow: true}}

	fresh := &fakeRoleWriter{}
	if err := ensureDynsecRole(context.Background(), fresh, "r", acls); err != nil || !slices.Equal(fresh.calls, []string{"createRole"}) {
		t.Fatalf("new role: calls %v err %v", fresh.calls, err)
	}

	existing := &fakeRoleWriter{createErr: errors.New("dynsec createRole: Role already exists")}
	if err := ensureDynsecRole(context.Background(), existing, "r", acls); err != nil ||
		!slices.Equal(existing.calls, []string{"createRole", "modifyRole"}) || !slices.Equal(existing.acls, acls) {
		t.Fatalf("existing role: calls %v acls %v err %v", existing.calls, existing.acls, err)
	}

	broken := &fakeRoleWriter{createErr: errors.New("dynsec createRole: timeout")}
	if err := ensureDynsecRole(context.Background(), broken, "r", acls); err == nil || len(broken.calls) != 1 {
		t.Fatalf("other error: calls %v err %v", broken.calls, err)
	}
}
