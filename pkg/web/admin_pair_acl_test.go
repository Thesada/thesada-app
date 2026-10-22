package web

import (
	"testing"

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
			got := map[string]string{}
			for _, a := range acls {
				if a.Topic == "homeassistant/#" {
					continue
				}
				if !a.Allow {
					t.Errorf("unexpected deny ACL %+v", a)
				}
				got[a.ACLType] = a.Topic
			}
			want := map[string]string{
				"publishClientSend":    prefix + "/#",
				"subscribePattern":     tc.wantRead,
				"publishClientReceive": tc.wantRead,
			}
			for k, v := range want {
				if got[k] != v {
					t.Errorf("%s = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}
