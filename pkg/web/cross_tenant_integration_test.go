//go:build integration

// Cross-tenant isolation for every web route that names a tenant-owned
// object (webCrossTenantRoutes). A user in tenant B aims each route at
// tenant A's objects: reads must 404 or show nothing of A, writes must leave
// A's rows in place. Each case also runs as A's owner, so a check that can
// never fail (two empty pages match) is caught. Revoke is the exception: its
// owner path needs the broker and is covered in device_revoke_integration_test.go.
//
//	go test -tags integration -run TestCrossTenant_WebRoutes ./pkg/web/...
package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service/servicetest"
)

const (
	ctTenantA   = "ct-a"
	ctTenantB   = "ct-b"
	ctDeviceID  = "thesada-c7c7c7c7c7c7"
	ctMetric    = "ct/canary"
	ctAlertText = "canary alert ct-a 7f3e"
)

// crossTenantFixture is tenant A's owned objects plus a session per tenant.
type crossTenantFixture struct {
	env        *servicetest.Env
	srv        http.Handler
	device     uuid.UUID
	sub        uuid.UUID
	identity   uuid.UUID
	owner, out *http.Cookie
}

// seedCrossTenant seeds tenant A (owner, paired device with telemetry, an
// alert, an alert subscription, an OIDC identity) and tenant B (one user).
// in: t. out: fixture.
func seedCrossTenant(t *testing.T) crossTenantFixture {
	t.Helper()
	ctx := context.Background()
	env := servicetest.Start(t)
	env.SeedTenant(t, ctTenantA)
	env.SeedTenant(t, ctTenantB)

	ownerID := mustWebUser(t, env, ctTenantA, "owner@ct-a.test", "correct-horse-a")
	outID := mustWebUser(t, env, ctTenantB, "outsider@ct-b.test", "correct-horse-b")
	session := func(tenant string, id uuid.UUID) *http.Cookie {
		tok, _, err := env.Services.Auth.CreateSession(tenant, id, "magic_link", "go-test", "127.0.0.1")
		if err != nil {
			t.Fatalf("session: %v", err)
		}
		return &http.Cookie{Name: authmw.CookieName, Value: tok}
	}

	pk, err := env.Services.Devices.Upsert(ctTenantA, ctDeviceID, "CT device", "1.0.0", "esp32", "thesada/"+ctTenantA+"/"+ctDeviceID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if _, err := env.Super.Exec(ctx, `UPDATE devices SET owner_user_id = $1 WHERE id = $2`, ownerID, pk); err != nil {
		t.Fatalf("set owner: %v", err)
	}
	now := time.Now()
	if err := env.Services.Certificates.Issue(ctx, ctTenantA, pk, "ct-serial", "ct-cn", now, now.Add(time.Hour), "pem"); err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	val := 42.0
	if _, err := env.Services.Telemetry.RecordTelemetry(ctx, ctTenantA, pk, ctMetric, &val, "", nil); err != nil {
		t.Fatalf("seed telemetry: %v", err)
	}
	if _, err := env.Services.Alerts.InsertAlert(ctx, ctTenantA, pk, "warn", "CT1", ctAlertText, nil); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	if err := env.Services.Alerts.CreateSubscription(ctx, ctTenantA, ownerID, &pk, "email", "warn", "owner@ct-a.test"); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}
	subs, err := env.Services.Alerts.ListSubscriptions(ctx, ctTenantA, ownerID)
	if err != nil || len(subs) != 1 {
		t.Fatalf("list subscriptions: %v (%d)", err, len(subs))
	}
	var provider, identity uuid.UUID
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO oauth_providers (tenant_id, slug, display_name, issuer_url, client_id, enabled)
		 VALUES ($1, 'ct-idp', 'CT IdP', 'https://idp.invalid', 'ct', true) RETURNING id`, ctTenantA).Scan(&provider); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO user_oauth_identities (user_id, provider_id, subject, email)
		 VALUES ($1, $2, 'ct-subject', 'owner@ct-a.test') RETURNING id`, ownerID, provider).Scan(&identity); err != nil {
		t.Fatalf("seed identity: %v", err)
	}

	return crossTenantFixture{
		env:      env,
		srv:      New(env.Cfg, env.Services, nil, nil, nil, nil),
		device:   pk,
		sub:      subs[0].ID,
		identity: identity,
		owner:    session(ctTenantA, ownerID),
		out:      session(ctTenantB, outID),
	}
}

// getAs sends a GET with the session cookie.
// in: handler, path, session. out: recorder.
func getAs(srv http.Handler, path string, session *http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// count runs a SELECT count(*) as the superuser.
// in: t, fixture, query, args. out: count.
func (f crossTenantFixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.env.Super.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

// wantHidden fails unless rec is a 404 or a page without the canary.
// in: t, recorder, canary text. out: none.
func wantHidden(t *testing.T, rec *httptest.ResponseRecorder, canary string) {
	t.Helper()
	if rec.Code != http.StatusNotFound && rec.Code != http.StatusOK {
		t.Fatalf("outsider status = %d, want 404 or an empty 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), canary) {
		t.Fatalf("outsider saw %q", canary)
	}
}

// wantShown fails unless rec is a 200 carrying the canary.
// in: t, recorder, canary text. out: none.
func wantShown(t *testing.T, rec *httptest.ResponseRecorder, canary string) {
	t.Helper()
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), canary) {
		t.Fatalf("owner status = %d, canary shown = %v; the check cannot fire",
			rec.Code, strings.Contains(rec.Body.String(), canary))
	}
}

func TestCrossTenant_WebRoutes(t *testing.T) {
	f := seedCrossTenant(t)
	dev := "/devices/" + f.device.String()

	cases := map[string]func(t *testing.T){
		"GET /devices": func(t *testing.T) {
			wantHidden(t, getAs(f.srv, "/devices", f.out), ctDeviceID)
			wantShown(t, getAs(f.srv, "/devices", f.owner), ctDeviceID)
		},
		"GET /devices/{id}": func(t *testing.T) {
			if rec := getAs(f.srv, dev, f.out); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			wantShown(t, getAs(f.srv, dev, f.owner), ctDeviceID)
		},
		"GET /devices/{id}/chart.json": func(t *testing.T) {
			path := dev + "/chart.json?metric=" + url.QueryEscape(ctMetric)
			if rec := getAs(f.srv, path, f.out); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			rec := getAs(f.srv, path, f.owner)
			var chart struct{ Avg []*float64 }
			if err := json.Unmarshal(rec.Body.Bytes(), &chart); err != nil || rec.Code != http.StatusOK ||
				len(chart.Avg) != 1 || chart.Avg[0] == nil || *chart.Avg[0] != 42 {
				t.Fatalf("owner chart = %d %s; the check cannot fire", rec.Code, rec.Body.String())
			}
		},
		"GET /alerts": func(t *testing.T) {
			wantHidden(t, getAs(f.srv, "/alerts", f.out), ctAlertText)
			wantShown(t, getAs(f.srv, "/alerts", f.owner), ctAlertText)
		},
		// Owner side: TestOwnerRevoke_* (needs the broker for cert.clear).
		"POST /devices/{id}/revoke": func(t *testing.T) {
			form := url.Values{"confirm_device_id": {ctDeviceID}}
			if rec := postAuthed(t, f.srv, dev+"/revoke", form, f.out, ""); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			if n := f.count(t, `SELECT count(*) FROM devices WHERE id = $1 AND paired_at IS NOT NULL`, f.device); n != 1 {
				t.Fatal("outsider revoke unpaired the device")
			}
		},
		"POST /devices/{id}/sensors/delete": func(t *testing.T) {
			form := url.Values{"metric": {ctMetric}, "confirm_metric": {ctMetric}}
			rows := `SELECT count(*) FROM device_telemetry WHERE device_pk = $1 AND metric = $2`
			if rec := postAuthed(t, f.srv, dev+"/sensors/delete", form, f.out, ""); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			if f.count(t, rows, f.device, ctMetric) != 1 {
				t.Fatal("outsider deleted tenant A's telemetry")
			}
			postAuthed(t, f.srv, dev+"/sensors/delete", form, f.owner, "")
			if f.count(t, rows, f.device, ctMetric) != 0 {
				t.Fatal("owner delete left the rows; the check cannot fire")
			}
		},
		"POST /settings/notifications/delete": func(t *testing.T) {
			form := url.Values{"sub_id": {f.sub.String()}}
			rows := `SELECT count(*) FROM alert_subscriptions WHERE id = $1`
			postAuthed(t, f.srv, "/settings/notifications/delete", form, f.out, "")
			if f.count(t, rows, f.sub) != 1 {
				t.Fatal("outsider deleted tenant A's subscription")
			}
			postAuthed(t, f.srv, "/settings/notifications/delete", form, f.owner, "")
			if f.count(t, rows, f.sub) != 0 {
				t.Fatal("owner delete left the subscription; the check cannot fire")
			}
		},
		"POST /settings/oauth/{id}/unlink": func(t *testing.T) {
			path := "/settings/oauth/" + f.identity.String() + "/unlink"
			rows := `SELECT count(*) FROM user_oauth_identities WHERE id = $1`
			postAuthed(t, f.srv, path, url.Values{}, f.out, "")
			if f.count(t, rows, f.identity) != 1 {
				t.Fatal("outsider unlinked tenant A's identity")
			}
			postAuthed(t, f.srv, path, url.Values{}, f.owner, "")
			if f.count(t, rows, f.identity) != 0 {
				t.Fatal("owner unlink left the identity; the check cannot fire")
			}
		},
	}

	for _, route := range webCrossTenantRoutes {
		run, ok := cases[route]
		if !ok {
			t.Errorf("no cross-tenant case for %q", route)
			continue
		}
		t.Run(route, run)
	}
	for route := range cases {
		if !slices.Contains(webCrossTenantRoutes, route) {
			t.Errorf("case %q is not in webCrossTenantRoutes", route)
		}
	}
}
