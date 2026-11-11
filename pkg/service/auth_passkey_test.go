package service

import (
	"math"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/config"
)

func TestSignCount32Clamps(t *testing.T) {
	cases := map[int64]uint32{-1: 0, 0: 0, 7: 7, math.MaxUint32: math.MaxUint32, math.MaxUint32 + 1: math.MaxUint32}
	for in, want := range cases {
		if got := signCount32(in); got != want {
			t.Errorf("signCount32(%d) = %d, want %d", in, got, want)
		}
	}
}

func TestNewRelyingPartyNeedsAnRPIDAndOrigins(t *testing.T) {
	if newRelyingParty(nil) != nil {
		t.Error("nil config must give no relying party")
	}
	if newRelyingParty(&config.Config{WebAuthnOrigins: []string{"https://a.test"}}) != nil {
		t.Error("missing RP ID must give no relying party")
	}
	if newRelyingParty(&config.Config{WebAuthnRPID: "a.test"}) != nil {
		t.Error("missing origins must give no relying party")
	}
	if newRelyingParty(&config.Config{WebAuthnRPID: "a.test", WebAuthnOrigins: []string{"https://a.test"}}) == nil {
		t.Error("a full config must give a relying party")
	}
}

func TestPasskeyUserNames(t *testing.T) {
	id := uuid.New()
	u := &passkeyUser{id: id, email: "a@b.test"}
	if string(u.WebAuthnID()) != string(id[:]) || u.WebAuthnName() != "a@b.test" || u.WebAuthnDisplayName() != "a@b.test" {
		t.Fatalf("defaults: %x %q %q", u.WebAuthnID(), u.WebAuthnName(), u.WebAuthnDisplayName())
	}
	u.displayName = "Ann"
	if u.WebAuthnDisplayName() != "Ann" {
		t.Fatalf("display name = %q", u.WebAuthnDisplayName())
	}
}
