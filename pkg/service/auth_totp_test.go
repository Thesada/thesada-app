package service

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestTOTPRequired_LookupErrorIsNotOff(t *testing.T) {
	_, err := TOTPRequired("", false, errors.New("db down"))
	if err == nil {
		t.Fatal("lookup error counted as TOTP off")
	}
}

func TestTOTPRequired_OffDoesNotChallenge(t *testing.T) {
	required, err := TOTPRequired("", false, nil)
	if err != nil || required {
		t.Fatalf("off account required=%v err=%v", required, err)
	}
}

func TestBeginTOTPLogin_RequiresMethod(t *testing.T) {
	s := &AuthService{}
	_, _, err := s.BeginTOTPLogin("tenant", uuid.MustParse("11111111-1111-1111-1111-111111111111"), "")
	if err == nil {
		t.Fatal("empty method started a challenge")
	}
}

func TestMatchTOTP_CorruptSecretIsError(t *testing.T) {
	ok, err := MatchTOTP("!!!", "000000")
	if ok || err == nil || !strings.HasPrefix(err.Error(), "totp: decode secret:") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
}

func TestAllowTOTPAttempt_EmptyIPSkipsTheCap(t *testing.T) {
	s := newThrottleSvc()
	for i := 0; i < loginMaxPerIP+5; i++ {
		if !s.AllowTOTPAttempt("") {
			t.Fatalf("empty-ip attempt %d was denied", i+1)
		}
	}
}

func TestAllowTOTPAttempt_PerIPCap(t *testing.T) {
	s := newThrottleSvc()
	for i := 0; i < loginMaxPerIP; i++ {
		if !s.AllowTOTPAttempt("198.51.100.8") {
			t.Fatalf("attempt %d under the cap was denied", i+1)
		}
	}
	if s.AllowTOTPAttempt("198.51.100.8") {
		t.Fatal("attempt over the per-IP cap was allowed")
	}
}

func TestTOTPRequired_EnrolledChallenges(t *testing.T) {
	required, err := TOTPRequired("SECRET", true, nil)
	if err != nil || !required {
		t.Fatalf("enrolled account required=%v err=%v", required, err)
	}
}
