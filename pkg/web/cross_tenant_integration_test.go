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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

const (
	ctTenantA     = "ct-a"
	ctTenantB     = "ct-b"
	ctDeviceID    = "thesada-c7c7c7c7c7c7"
	ctMetric      = "ct/canary"
	ctAlertText   = "canary alert ct-a 7f3e"
	ctTrendMetric = "ct.trendcanary"
)

// Passwords of the two seeded users, for routes that re-check one.
const (
	ctPasswordA = "correct-horse-a"
	ctPasswordB = "correct-horse-b"
)

// crossTenantFixture is tenant A's owned objects plus a session per tenant.
type crossTenantFixture struct {
	env        *servicetest.Env
	srv        http.Handler
	device     uuid.UUID
	sub        uuid.UUID
	identity   uuid.UUID
	passkey    int64
	channels   map[string]uuid.UUID
	rules      map[string]uuid.UUID
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

	ownerID := mustWebUser(t, env, ctTenantA, "owner@ct-a.test", ctPasswordA)
	outID := mustWebUser(t, env, ctTenantB, "outsider@ct-b.test", ctPasswordB)
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
	channels := map[string]uuid.UUID{}
	for _, name := range []string{"update", "toggle", "delete", "rule"} {
		id, err := env.Services.Alerts.CreateChannel(ctx, ctTenantA, ownerID, "telegram", "-100"+strconv.Itoa(len(channels)+1), name)
		if err != nil {
			t.Fatalf("seed channel %s: %v", name, err)
		}
		channels[name] = id
	}
	rules := map[string]uuid.UUID{}
	for _, name := range []string{"toggle", "delete"} {
		id, err := env.Services.Alerts.CreateTrendRule(ctx, ctTenantA, service.TrendRule{
			Metric: ctTrendMetric, Direction: "fall", Delta: 1, WindowS: 600, Severity: "warn", DevicePK: &pk,
		})
		if err != nil {
			t.Fatalf("seed trend rule %s: %v", name, err)
		}
		rules[name] = id
	}
	var passkey int64
	if err := env.Super.QueryRow(ctx,
		`INSERT INTO user_passkeys (user_id, credential_id, public_key, name)
		 VALUES ($1, 'ct-credential', '\x00', 'ct key') RETURNING id`, ownerID).Scan(&passkey); err != nil {
		t.Fatalf("seed passkey: %v", err)
	}

	return crossTenantFixture{
		env:      env,
		srv:      New(env.Cfg, env.Services, nil, nil, nil, nil),
		device:   pk,
		sub:      subs[0].ID,
		identity: identity,
		passkey:  passkey,
		channels: channels,
		rules:    rules,
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
			wantHidden(t, getAs(f.srv, "/alerts", f.out), ctTrendMetric)
			wantShown(t, getAs(f.srv, "/alerts", f.owner), ctTrendMetric)
		},
		"POST /alerts/rules/add": func(t *testing.T) {
			form := url.Values{"metric": {"ct.added"}, "direction": {"rise"}, "delta": {"2"},
				"window": {"10"}, "unit": {"min"}, "severity": {"warn"}, "device": {f.device.String()}}
			rows := `SELECT count(*) FROM alert_rules WHERE metric = 'ct.added'`
			if rec := postAuthed(t, f.srv, "/alerts/rules/add", form, f.out, ""); rec.Code != http.StatusBadRequest {
				t.Fatalf("outsider on A's device: status %d, want 400", rec.Code)
			}
			if f.count(t, rows) != 0 {
				t.Fatal("outsider added a rule on tenant A's device")
			}
			postAuthed(t, f.srv, "/alerts/rules/add", form, f.owner, "")
			if f.count(t, rows) != 1 {
				t.Fatal("owner rule did not land; the check cannot fire")
			}
		},
		"POST /alerts/rules/{id}/toggle": func(t *testing.T) {
			id := f.rules["toggle"]
			path := "/alerts/rules/" + id.String() + "/toggle"
			rows := `SELECT count(*) FROM alert_rules WHERE id = $1 AND enabled`
			if rec := postAuthed(t, f.srv, path, url.Values{}, f.out, ""); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			if f.count(t, rows, id) != 1 {
				t.Fatal("outsider switched off tenant A's rule")
			}
			postAuthed(t, f.srv, path, url.Values{}, f.owner, "")
			if f.count(t, rows, id) != 0 {
				t.Fatal("owner toggle did not land; the check cannot fire")
			}
		},
		"POST /alerts/rules/{id}/delete": func(t *testing.T) {
			id := f.rules["delete"]
			path := "/alerts/rules/" + id.String() + "/delete"
			rows := `SELECT count(*) FROM alert_rules WHERE id = $1`
			if rec := postAuthed(t, f.srv, path, url.Values{}, f.out, ""); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			if f.count(t, rows, id) != 1 {
				t.Fatal("outsider removed tenant A's rule")
			}
			postAuthed(t, f.srv, path, url.Values{}, f.owner, "")
			if f.count(t, rows, id) != 0 {
				t.Fatal("owner removal left the rule; the check cannot fire")
			}
		},
		"GET /devices/{id}/rules": func(t *testing.T) {
			if rec := getAs(f.srv, dev+"/rules", f.out); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			wantShown(t, getAs(f.srv, dev+"/rules", f.owner), ctDeviceID)
		},
		"GET /devices/{id}/rules/workspace": func(t *testing.T) {
			if rec := getAs(f.srv, dev+"/rules/workspace", f.out); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			wantShown(t, getAs(f.srv, dev+"/rules/workspace", f.owner), `"exists"`)
		},
		"POST /devices/{id}/rules/preview": func(t *testing.T) {
			body := tenantRulesJSON(t, testRuleFields())
			if rec := postPasskeyJSON(t, f.srv, dev+"/rules/preview", body, f.out); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			wantShown(t, postPasskeyJSON(t, f.srv, dev+"/rules/preview", body, f.owner), "EventBus.subscribe")
		},
		"POST /devices/{id}/rules/workspace": func(t *testing.T) {
			rows := `SELECT count(*) FROM device_rule_workspaces WHERE device_pk = $1`
			body := tenantRulesJSON(t, testRuleFields())
			if rec := postPasskeyJSON(t, f.srv, dev+"/rules/workspace", body, f.out); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			if f.count(t, rows, f.device) != 0 {
				t.Fatal("outsider saved rules on tenant A's device")
			}
			postPasskeyJSON(t, f.srv, dev+"/rules/workspace", body, f.owner)
			if f.count(t, rows, f.device) != 1 {
				t.Fatal("owner save stored nothing; the check cannot fire")
			}
		},
		"POST /devices/{id}/rules/push": func(t *testing.T) {
			if rec := postPasskeyJSON(t, f.srv, dev+"/rules/push", []byte("{}"), f.out); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			// No rules saved yet in this case's view: the owner gets past the scope check.
			if rec := postPasskeyJSON(t, f.srv, dev+"/rules/push", []byte("{}"), f.owner); rec.Code == http.StatusNotFound {
				t.Fatal("owner push was a 404; the check cannot fire")
			}
		},
		"GET /devices/{id}/rules/push/result": func(t *testing.T) {
			path := dev + "/rules/push/result?id=" + uuid.NewString()
			if rec := getAs(f.srv, path, f.out); rec.Code != http.StatusNotFound {
				t.Fatalf("outsider status = %d, want 404", rec.Code)
			}
			wantShown(t, getAs(f.srv, path, f.owner), `"expired"`)
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
		"POST /settings/notifications/add": func(t *testing.T) {
			ch := f.channels["rule"]
			form := url.Values{"channel_id": {ch.String()}, "min_severity": {"warn"}}
			rows := `SELECT count(*) FROM alert_subscriptions WHERE channel_id = $1`
			postAuthed(t, f.srv, "/settings/notifications/add", form, f.out, "")
			if f.count(t, rows, ch) != 0 {
				t.Fatal("outsider subscribed tenant A's channel")
			}
			postAuthed(t, f.srv, "/settings/notifications/add", form, f.owner, "")
			if f.count(t, rows, ch) != 1 {
				t.Fatal("owner rule did not land; the check cannot fire")
			}
		},
		"POST /settings/channels/{id}/update": func(t *testing.T) {
			ch := f.channels["update"]
			path := "/settings/channels/" + ch.String() + "/update"
			rows := `SELECT count(*) FROM notification_channels WHERE id = $1 AND target = '-100999'`
			form := url.Values{"target": {"-100999"}, "label": {"x"}, "enabled": {"on"}}
			postAuthed(t, f.srv, path, form, f.out, "")
			if f.count(t, rows, ch) != 0 {
				t.Fatal("outsider edited tenant A's channel")
			}
			postAuthed(t, f.srv, path, form, f.owner, "")
			if f.count(t, rows, ch) != 1 {
				t.Fatal("owner edit did not land; the check cannot fire")
			}
		},
		"POST /settings/channels/{id}/toggle": func(t *testing.T) {
			ch := f.channels["toggle"]
			path := "/settings/channels/" + ch.String() + "/toggle"
			rows := `SELECT count(*) FROM notification_channels WHERE id = $1 AND enabled`
			form := url.Values{"enabled": {"false"}}
			postAuthed(t, f.srv, path, form, f.out, "")
			if f.count(t, rows, ch) != 1 {
				t.Fatal("outsider switched off tenant A's channel")
			}
			postAuthed(t, f.srv, path, form, f.owner, "")
			if f.count(t, rows, ch) != 0 {
				t.Fatal("owner toggle did not land; the check cannot fire")
			}
		},
		"POST /settings/channels/{id}/delete": func(t *testing.T) {
			ch := f.channels["delete"]
			path := "/settings/channels/" + ch.String() + "/delete"
			rows := `SELECT count(*) FROM notification_channels WHERE id = $1`
			postAuthed(t, f.srv, path, url.Values{}, f.out, "")
			if f.count(t, rows, ch) != 1 {
				t.Fatal("outsider removed tenant A's channel")
			}
			postAuthed(t, f.srv, path, url.Values{}, f.owner, "")
			if f.count(t, rows, ch) != 0 {
				t.Fatal("owner removal left the channel; the check cannot fire")
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
		"POST /settings/passkeys/{id}/delete": func(t *testing.T) {
			path := "/settings/passkeys/" + strconv.FormatInt(f.passkey, 10) + "/delete"
			rows := `SELECT count(*) FROM user_passkeys WHERE id = $1`
			postAuthed(t, f.srv, path, url.Values{"password": {ctPasswordB}}, f.out, "")
			if f.count(t, rows, f.passkey) != 1 {
				t.Fatal("outsider removed tenant A's passkey")
			}
			postAuthed(t, f.srv, path, url.Values{"password": {ctPasswordA}}, f.owner, "")
			if f.count(t, rows, f.passkey) != 0 {
				t.Fatal("owner removal left the passkey; the check cannot fire")
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
