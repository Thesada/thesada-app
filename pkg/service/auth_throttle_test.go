package service

import (
	"fmt"
	"testing"

	"thesada.app/app/pkg/ratelimit"
)

// newThrottleSvc builds an AuthService with live login limiters but no sweeper
// goroutines (allowLogin only consults the limiters) and no pools.
func newThrottleSvc() *AuthService {
	return &AuthService{
		loginEmailLimits: ratelimit.New(loginWindow, loginMaxPerEmail),
		loginIPLimits:    ratelimit.New(loginWindow, loginMaxPerIP),
	}
}

// TestAllowLogin_PerEmailCap pins the per-account brake on online guessing.
func TestAllowLogin_PerEmailCap(t *testing.T) {
	s := newThrottleSvc()
	for i := 0; i < loginMaxPerEmail; i++ {
		if !s.allowLogin("cap@x.test", "") {
			t.Fatalf("attempt %d under cap was denied", i+1)
		}
	}
	if s.allowLogin("cap@x.test", "") {
		t.Error("attempt over the per-email cap was allowed")
	}
}

// TestAllowLogin_PerIPCap pins the per-source brake; distinct emails keep the
// per-email bucket from tripping first.
func TestAllowLogin_PerIPCap(t *testing.T) {
	s := newThrottleSvc()
	for i := 0; i < loginMaxPerIP; i++ {
		if !s.allowLogin(fmt.Sprintf("ipuser-%d@x.test", i), "198.51.100.7") {
			t.Fatalf("ip attempt %d under cap was denied", i+1)
		}
	}
	if s.allowLogin("ipuser-over@x.test", "198.51.100.7") {
		t.Error("attempt over the per-IP cap was allowed")
	}
}

// TestAllowLogin_EmptyIPSkipsIPBucket confirms a missing IP does not collapse
// every IP-less attempt into one shared bucket.
func TestAllowLogin_EmptyIPSkipsIPBucket(t *testing.T) {
	s := newThrottleSvc()
	for i := 0; i < loginMaxPerIP+5; i++ {
		if !s.allowLogin(fmt.Sprintf("noip-%d@x.test", i), "") {
			t.Fatalf("empty-ip attempt %d denied; per-IP bucket should be skipped", i+1)
		}
	}
}

// TestAllowLogin_EmailKeyCaseInsensitive stops case variation from minting a
// fresh per-email bucket per spelling of the same address.
func TestAllowLogin_EmailKeyCaseInsensitive(t *testing.T) {
	s := newThrottleSvc()
	for i := 0; i < loginMaxPerEmail; i++ {
		s.allowLogin("Case@X.test", "")
	}
	if s.allowLogin("case@x.test", "") {
		t.Error("case variant got a fresh bucket; email key not normalised")
	}
}
