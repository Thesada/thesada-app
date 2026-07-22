// Unit coverage for the cert.issue audit detail shape: both lifecycle
// outcomes keep the same identifying keys, and the failure stage only
// appears when a stage actually died.
package web

import (
	"testing"

	"thesada.app/app/pkg/service"
)

func TestPairIssueDetail(t *testing.T) {
	t.Run("success_has_status_no_stage", func(t *testing.T) {
		d := pairIssueDetail("owb-1", "cn-1", "abc", service.CertStatusActive, "")
		if d["status"] != service.CertStatusActive {
			t.Errorf("status = %v, want active", d["status"])
		}
		if _, ok := d["stage"]; ok {
			t.Error("success detail carries a stage key")
		}
		for _, k := range []string{"device_id", "cn", "serial"} {
			if d[k] == "" || d[k] == nil {
				t.Errorf("detail missing %q", k)
			}
		}
	})

	t.Run("failure_names_the_stage", func(t *testing.T) {
		d := pairIssueDetail("owb-1", "cn-1", "abc", service.CertStatusFailed, "push_client_key")
		if d["status"] != service.CertStatusFailed || d["stage"] != "push_client_key" {
			t.Errorf("detail = %v, want failed + push_client_key", d)
		}
	})
}
