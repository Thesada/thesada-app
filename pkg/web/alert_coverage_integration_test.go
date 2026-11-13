//go:build integration

package web

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service/servicetest"
)

const unheardBanner = "Nobody gets alerts for this tenant."

// The banner shows on /devices and /alerts while the tenant has a paired device
// and no subscriber, and goes once someone subscribes. The admin tenants list
// shows the subscriber count.
func TestAlertCoverageBanner(t *testing.T) {
	env := servicetest.Start(t)
	srv := New(env.Cfg, env.Services, nil, nil, nil, nil)
	ctx := context.Background()
	const tenant = "cov-web"
	env.SeedTenant(t, tenant)
	uid := mustWebUser(t, env, tenant, "cov@web.test", "")
	tok, _, err := env.Services.Auth.CreateSession(tenant, uid, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	session := &http.Cookie{Name: authmw.CookieName, Value: tok}
	page := func(path string) string {
		t.Helper()
		rec := getAs(srv, path, session)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s = %d", path, rec.Code)
		}
		return rec.Body.String()
	}
	wantBanner := func(want bool) {
		t.Helper()
		for _, p := range []string{"/devices", "/alerts"} {
			body := page(p)
			if got := strings.Contains(body, unheardBanner); got != want {
				t.Fatalf("%s banner shown = %v, want %v", p, got, want)
			}
			if want && !strings.Contains(body, `href="/settings#notifications"`) {
				t.Fatalf("%s banner has no link to the alert settings", p)
			}
		}
	}

	pk, err := env.Services.Devices.Upsert(tenant, "cov-web-dev", "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	wantBanner(false) // an unpaired device raises nothing worth a banner

	if _, err := env.Super.Exec(ctx, `UPDATE devices SET paired_at = now() WHERE id = $1`, pk); err != nil {
		t.Fatal(err)
	}
	wantBanner(true)

	// Pairing through the service subscribes the user, and the banner goes.
	now := time.Now()
	if err := env.Services.Certificates.Issue(ctx, tenant, pk, "cov-web-s", "cov-web-cn", now, now.Add(time.Hour), "pem"); err != nil {
		t.Fatal(err)
	}
	wantBanner(false)

	// The admin tenants list counts that subscriber.
	root := mustWebUser(t, env, tenant, "root@web.test", "")
	if _, err := env.Super.Exec(ctx, `UPDATE users SET is_super_admin = true WHERE id = $1`, root); err != nil {
		t.Fatal(err)
	}
	rtok, _, err := env.Services.Auth.CreateSession(tenant, root, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	rec := getAs(srv, "/admin/tenants", &http.Cookie{Name: authmw.CookieName, Value: rtok})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/tenants = %d", rec.Code)
	}
	if !regexp.MustCompile(`(?s)` + tenant + `.*?data-subscribers="1"`).MatchString(rec.Body.String()) {
		t.Fatal("admin tenants list does not show 1 subscriber for the tenant")
	}
}
