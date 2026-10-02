package service

import (
	"testing"
	"time"
)

func TestCanonicalCertSerial(t *testing.T) {
	ok40 := "1234567890abcdef1234567890abcdef12345678"
	if len(ok40) != 40 {
		t.Fatalf("fixture length %d", len(ok40))
	}
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"ab", "ab", true},
		{"00ab", "ab", true},
		{"0", "0", true},
		{"00", "0", true},
		{"AB", "", false},
		{"", "", false},
		{"zz", "", false},
		{ok40, ok40, true},
		{ok40 + "a", "", false},
	}
	for _, c := range cases {
		got, ok := CanonicalCertSerial(c.in)
		if ok != c.ok || got != c.want {
			t.Errorf("CanonicalCertSerial(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestEnrollStatusMessageMatchesFirmware(t *testing.T) {
	got := EnrollStatusMessage("thesada-aabbccddeeff", "ab", 1767225600)
	want := "thesada-enroll-status\nthesada-aabbccddeeff\nab\n1767225600"
	if got != want {
		t.Fatalf("message = %q, want %q", got, want)
	}
}

func TestEnrollStatusFresh(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	if !EnrollStatusFresh(now, now.Unix()) {
		t.Fatal("now must be fresh")
	}
	if !EnrollStatusFresh(now, now.Add(-EnrollStatusSkew).Unix()) {
		t.Fatal("edge of the window must be fresh")
	}
	if EnrollStatusFresh(now, now.Add(-EnrollStatusSkew-time.Second).Unix()) {
		t.Fatal("past the window must be stale")
	}
	if EnrollStatusFresh(now, now.Add(EnrollStatusSkew+time.Second).Unix()) {
		t.Fatal("future past the window must be stale")
	}
}

func TestCertRevocationAnswer(t *testing.T) {
	const id, pub = "thesada-aabbccddeeff", "abababababababababababababababababababababababababababababababab"
	active := &CertStatusRow{Status: CertStatusActive, PubkeyHex: pub, DeviceID: id}
	revoked := &CertStatusRow{Revoked: true, Status: CertStatusActive, PubkeyHex: pub, DeviceID: id}
	pending := &CertStatusRow{Status: CertStatusPending, PubkeyHex: pub, DeviceID: id}
	noKey := &CertStatusRow{Status: CertStatusActive, DeviceID: id}
	tomb := &CertSerialTombstone{DeviceID: id, PubkeyHex: pub}

	if got := CertRevocationAnswer(id, pub, active, nil); got != EnrollStatusActive {
		t.Errorf("active = %s", got)
	}
	if got := CertRevocationAnswer(id, pub, revoked, nil); got != EnrollStatusRevoked {
		t.Errorf("revoked = %s", got)
	}
	if got := CertRevocationAnswer(id, pub, pending, nil); got != EnrollStatusUnknown {
		t.Errorf("pending = %s", got)
	}
	if got := CertRevocationAnswer(id, pub, noKey, nil); got != EnrollStatusUnknown {
		t.Errorf("null pubkey = %s", got)
	}
	if got := CertRevocationAnswer(id, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", active, nil); got != EnrollStatusUnknown {
		t.Errorf("wrong key = %s", got)
	}
	if got := CertRevocationAnswer("thesada-000000000000", pub, active, nil); got != EnrollStatusUnknown {
		t.Errorf("wrong device = %s", got)
	}
	if got := CertRevocationAnswer(id, pub, nil, tomb); got != EnrollStatusRevoked {
		t.Errorf("tombstone = %s", got)
	}
	if got := CertRevocationAnswer(id, pub, nil, nil); got != EnrollStatusUnknown {
		t.Errorf("missing = %s", got)
	}
	if got := CertRevocationAnswer(id, pub, active, tomb); got != EnrollStatusActive {
		t.Errorf("live row must win over a tombstone, got %s", got)
	}
}
