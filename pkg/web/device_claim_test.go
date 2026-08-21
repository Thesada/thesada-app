package web

import (
	"strings"
	"testing"

	"thesada.app/app/pkg/config"
)

// The claim page must never render a browsable list of unclaimed devices.
// Enrollments carry no tenant, so any such list is cross-tenant by
// construction, and device ids come from sequentially-assigned MACs - one unit
// reveals its neighbours. Possession of the claim token is the authorisation.
func TestClaimTemplateHasNoDeviceListing(t *testing.T) {
	raw, err := templatesFS.ReadFile("templates/device-claim.html")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	body := string(raw)
	for _, forbidden := range []string{"range .Enrollments", "range .Devices", "range .Claimable"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("claim template must not enumerate devices, found %q", forbidden)
		}
	}
	if !strings.Contains(body, `name="claim_token"`) {
		t.Fatal("claim form must require a claim token")
	}
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Fatal("state-changing form must carry a CSRF token")
	}
}

// The claim token is the bearer credential for certificate delivery, and its
// stored hash is unsalted SHA-256. Neither it nor the pubkey may reach a page.
func TestClaimTemplateLeaksNoSecrets(t *testing.T) {
	raw, err := templatesFS.ReadFile("templates/device-claim.html")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	body := string(raw)
	for _, forbidden := range []string{"ClaimTokenHash", "PubkeyHex", "Challenge", "KeyPEM", "key_pem"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("claim template must not reference %q", forbidden)
		}
	}
}

// The prefix written into the broker ACL at claim time and the one handed to
// the device by the enrollment API must be the same string, or every publish
// the device makes is denied. Both derive it the same way; this pins the shape.
func TestDeviceClaimTopicPrefixShape(t *testing.T) {
	s := &Server{}
	got := s.deviceClaimTopicPrefix("acme", "thesada-0123456789ab")
	if got != "thesada/acme/thesada-0123456789ab" {
		t.Fatalf("unexpected prefix %q", got)
	}
}

// The spec sets 5 claims per user per hour; the shipped default was 20. The
// cap is config-driven so a fleet rollout does not need a rebuild, and a
// zero-valued config falls back to the spec figure rather than to unlimited.
func TestClaimLimiterHonoursConfiguredCap(t *testing.T) {
	l := newClaimLimiter(&config.Config{DeviceClaimMaxPerHour: 5})
	for i := 0; i < 5; i++ {
		if !l.Allow("user-1") {
			t.Fatalf("claim %d must be allowed under a cap of 5", i+1)
		}
	}
	if l.Allow("user-1") {
		t.Fatal("the 6th claim in the window must be refused")
	}
	if !l.Allow("user-2") {
		t.Fatal("the cap is per user, not global")
	}
}

func TestClaimLimiterFallsBackToSpecDefault(t *testing.T) {
	for _, cfg := range []*config.Config{nil, {}, {DeviceClaimMaxPerHour: 0}} {
		l := newClaimLimiter(cfg)
		for i := 0; i < claimRateFallback; i++ {
			if !l.Allow("user") {
				t.Fatalf("claim %d must be allowed under the fallback cap", i+1)
			}
		}
		if l.Allow("user") {
			t.Fatal("fallback must be a real cap, not unlimited")
		}
	}
}
