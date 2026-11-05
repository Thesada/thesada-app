//go:build integration

// One reset link sets one password: concurrent POSTs with the same token
// have exactly one winner.
//
//	go test -tags integration -run TestResetPasswordWeb ./pkg/web/...
package web

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"testing"

	"thesada.app/app/pkg/csrf"
	"thesada.app/app/pkg/service/servicetest"
)

func TestResetPasswordWeb_ConcurrentPostsHaveOneWinner(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	const tenant = "reset-web"
	const email = "reset@a.test"
	env.SeedTenant(t, tenant)
	uid := mustWebUser(t, env, tenant, email, "")
	token, _, err := env.Services.Auth.CreateResetLink(uid)
	if err != nil {
		t.Fatal(err)
	}
	csrfTok := csrfCookie(t, srv)

	const racers = 8
	codes := make([]int, racers)
	locs := make([]string, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pw := fmt.Sprintf("racer-%d-password", i)
			form := url.Values{"token": {token}, "password": {pw}, "confirm": {pw}, csrf.FormField: {csrfTok.Value}}
			<-start
			rec := submitForm(srv, "/reset-password", form, []*http.Cookie{csrfTok}, fmt.Sprintf("192.0.2.%d:1234", i+1))
			codes[i], locs[i] = rec.Code, rec.Header().Get("Location")
		}(i)
	}
	close(start)
	wg.Wait()

	winner := -1
	for i := 0; i < racers; i++ {
		if codes[i] == http.StatusFound && locs[i] == "/login" {
			if winner >= 0 {
				t.Fatalf("racers %d and %d both reset the password (codes %v)", winner, i, codes)
			}
			winner = i
		}
	}
	if winner < 0 {
		t.Fatalf("no racer reset the password (codes %v)", codes)
	}
	if _, err := env.Services.Auth.VerifyPassword(tenant, email, fmt.Sprintf("racer-%d-password", winner)); err != nil {
		t.Fatalf("winner's password does not verify: %v", err)
	}
}
