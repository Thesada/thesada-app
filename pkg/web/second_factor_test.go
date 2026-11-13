package web

import "testing"

// The second-factor page always offers a way on or says why there is none.
func TestSecondFactorOffer(t *testing.T) {
	cases := []struct {
		name                           string
		totpOn, keys, passkeysOn, fail bool
		wantTOTP, wantKey, wantMsg     bool
	}{
		{"totp only", true, false, true, false, true, false, false},
		{"passkey only", false, true, true, false, false, true, false},
		{"both", true, true, true, false, true, true, false},
		{"lookup failed", false, false, true, true, true, false, false},
		{"passkey only, passkeys off", false, true, false, false, false, false, true},
		{"both, passkeys off", true, true, false, false, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			totp, key, msg := secondFactorOffer(tc.totpOn, tc.keys, tc.passkeysOn, tc.fail)
			if totp != tc.wantTOTP || key != tc.wantKey || (msg != "") != tc.wantMsg {
				t.Fatalf("offer = totp %v key %v msg %q, want totp %v key %v msg %v",
					totp, key, msg, tc.wantTOTP, tc.wantKey, tc.wantMsg)
			}
		})
	}
}
