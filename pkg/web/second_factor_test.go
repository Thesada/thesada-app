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
		{"no factor left", false, false, true, false, false, false, true},
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

// With no factor left, the page says to sign in again even when a retry error came along.
func TestSecondFactorPage_NoFactorMessageWins(t *testing.T) {
	_, _, msg := secondFactorOffer(false, false, true, false)
	retry := map[string]interface{}{"Error": "Too many attempts. Wait a few minutes and try again."}
	if got := secondFactorPage(false, false, msg, retry)["Error"]; got != msg {
		t.Fatalf("Error = %q, want %q", got, msg)
	}
	if got := secondFactorPage(true, false, "", retry)["Error"]; got != retry["Error"] {
		t.Fatalf("with a factor, Error = %q, want the retry error", got)
	}
}
