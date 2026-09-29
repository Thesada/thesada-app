package web

import (
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
)

func TestOwnerRevoke_OnlyOwnerOrSuperAdmin_OnHeldOwnedDevice(t *testing.T) {
	owner := uuid.New()
	claimed := &service.Device{OwnerUserID: &owner}
	unowned := &service.Device{}
	ownerUser := &service.User{ID: owner}
	member := &service.User{ID: uuid.New()}
	admin := &service.User{ID: uuid.New(), IsSuperAdmin: true}
	cases := []struct {
		name string
		me   *service.User
		d    *service.Device
		hold service.DeviceHold
		want revokeVerdict
	}{
		{"owner on a held device", ownerUser, claimed, service.HoldHere, revokeAllowed},
		{"super-admin on a held owned device", admin, claimed, service.HoldHere, revokeAllowed},
		{"tenant member who is not the owner", member, claimed, service.HoldHere, revokeDenied},
		{"anonymous", nil, claimed, service.HoldHere, revokeDenied},
		{"no device", ownerUser, nil, service.HoldHere, revokeDenied},
		{"super-admin on an admin-paired device", admin, unowned, service.HoldHere, revokeNoOwner},
		{"member on an admin-paired device stays hidden", member, unowned, service.HoldHere, revokeDenied},
		{"old owner after the unit was claimed elsewhere", ownerUser, claimed, service.HoldElsewhere, revokeNotHeld},
		{"super-admin after the unit was claimed elsewhere", admin, claimed, service.HoldElsewhere, revokeNotHeld},
		{"owner re-posting after the revoke went through", ownerUser, claimed, service.HoldNone, revokeAlready},
		{"member on an already revoked device stays hidden", member, claimed, service.HoldNone, revokeDenied},
	}
	for _, c := range cases {
		if got := decideRevoke(c.me, c.d, c.hold); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestOwnerRevoke_AuditNamesWhoActed(t *testing.T) {
	owner := uuid.New()
	d := &service.Device{OwnerUserID: &owner}
	if got := revokePath(&service.User{ID: owner}, d); got != "owner" {
		t.Fatalf("owner path = %q, want owner", got)
	}
	if got := revokePath(&service.User{ID: uuid.New(), IsSuperAdmin: true}, d); got != "super_admin" {
		t.Fatalf("super-admin path = %q, want super_admin", got)
	}
}

func TestOwnerRevoke_EveryRefusalHasAMessage(t *testing.T) {
	for _, v := range []revokeVerdict{revokeNoOwner, revokeNotHeld, revokeAlready} {
		if _, ok := revokeRefusal[v]; !ok {
			t.Errorf("verdict %d has no refusal message", v)
		}
	}
	for _, v := range []revokeVerdict{revokeDenied, revokeAllowed} {
		if _, ok := revokeRefusal[v]; ok {
			t.Errorf("verdict %d must not map to a refusal message", v)
		}
	}
}

func TestOwnerRevoke_RequiresTypedDeviceID(t *testing.T) {
	cases := []struct {
		typed, id string
		want      bool
	}{
		{"thesada-0123456789ab", "thesada-0123456789ab", true},
		{"  thesada-0123456789ab ", "thesada-0123456789ab", true},
		{"thesada-0123456789ac", "thesada-0123456789ab", false},
		{"", "thesada-0123456789ab", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := revokeConfirmed(c.typed, c.id); got != c.want {
			t.Errorf("revokeConfirmed(%q, %q) = %v, want %v", c.typed, c.id, got, c.want)
		}
	}
}

func TestDeviceFlash_RendersOnlyRegisteredCodes(t *testing.T) {
	flashOf := func(target string) (string, string) {
		t.Helper()
		u, err := url.Parse(target)
		if err != nil {
			t.Fatalf("parse %q: %v", target, err)
		}
		return deviceFlash(u.Query())
	}
	if ok, bad := flashOf(flashRevoked.on("/d")); ok == "" || bad != "" {
		t.Fatalf("a success code must render as success only, got %q %q", ok, bad)
	}
	if ok, bad := flashOf(flashRevokeFailed.on("/d")); ok != "" || bad == "" {
		t.Fatalf("an error code must render as error only, got %q %q", ok, bad)
	}
	if ok, bad := flashOf("/d?ok=you+have+been+hacked&error=%3Cscript%3E"); ok != "" || bad != "" {
		t.Fatalf("unregistered codes must render nothing, got %q %q", ok, bad)
	}
	if ok, _ := flashOf("/d?ok=revoke_failed"); ok != "" {
		t.Fatal("an error code must not render as success")
	}
}

func TestDeviceFlash_RefusesDuplicateRegistration(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("registering a code twice must panic")
		}
	}()
	deviceFlashErr(flashRevokeFailed.code, "second text")
}

func TestDeviceDetail_RevokeFormCarriesCSRFAndTypedConfirm(t *testing.T) {
	raw, err := templatesFS.ReadFile("templates/device-detail.html")
	if err != nil {
		t.Fatalf("read template: %v", err)
	}
	body := string(raw)
	start := strings.Index(body, "{{if .CanRevoke}}")
	if start < 0 {
		t.Fatal("revoke section must be gated on .CanRevoke")
	}
	section := body[start:]
	for _, want := range []string{
		`action="/devices/{{.Device.ID}}/revoke"`,
		`name="_csrf"`,
		`name="confirm_device_id"`,
	} {
		if !strings.Contains(section, want) {
			t.Fatalf("revoke form missing %q", want)
		}
	}
}
