//go:build integration

// Cross-tenant isolation for every /api/v1 route that names a tenant-owned
// object (apiCrossTenantRoutes). A bearer token from tenant B aims each route
// at tenant A: reads must 404 or return nothing of A, the delete must leave
// A's row. Each case also runs with A's token, so a check that can never
// fail is caught.
//
//	go test -tags integration -run TestCrossTenant_APIRoutes ./pkg/api/v1/...
package v1_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"

	apiv1 "thesada.app/app/pkg/api/v1"
	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service/servicetest"
)

func TestCrossTenant_APIRoutes(t *testing.T) {
	env := servicetest.Start(t)
	srv := authmw.APIMiddleware(env.Services.Auth, env.Services.ApiTokens, authmw.APICSRFGuard{}, nil)(apiv1.New(env.Cfg, env.Services, nil, nil))
	ctx := context.Background()

	const (
		tA, tB    = "ctapi-a", "ctapi-b"
		devID     = "ctapi-dev-7f3e"
		alertText = "canary alert ctapi 7f3e"
		metric    = "ctapi/canary"
	)
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)
	bearer := func(tenant, email string) (map[string]string, uuid.UUID) {
		u, err := env.Services.Auth.CreateUser(tenant, email, email, false)
		if err != nil {
			t.Fatalf("seed user: %v", err)
		}
		tok, _, err := env.Services.ApiTokens.IssueToken(tenant, u.ID, "ct")
		if err != nil {
			t.Fatalf("issue token: %v", err)
		}
		return map[string]string{"Authorization": "Bearer " + tok}, u.ID
	}
	owner, ownerID := bearer(tA, "owner@ctapi-a.test")
	out, _ := bearer(tB, "outsider@ctapi-b.test")

	pk, err := env.Services.Devices.Upsert(tA, devID, "CT", "1.0.0", "esp32", "thesada/"+tA+"/"+devID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	val := 42.0
	if _, err := env.Services.Telemetry.RecordTelemetry(ctx, tA, pk, metric, &val, "", nil); err != nil {
		t.Fatalf("seed telemetry: %v", err)
	}
	if _, err := env.Services.Alerts.InsertAlert(ctx, tA, pk, "warn", "CT1", alertText, nil); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	if err := env.Services.Alerts.CreateSubscription(ctx, tA, ownerID, &pk, "email", "warn", "owner@ctapi-a.test"); err != nil {
		t.Fatalf("seed subscription: %v", err)
	}
	subs, err := env.Services.Alerts.ListSubscriptions(ctx, tA, ownerID)
	if err != nil || len(subs) != 1 {
		t.Fatalf("list subscriptions: %v (%d)", err, len(subs))
	}
	sub := subs[0].ID.String()
	subRows := func() int {
		var n int
		if err := env.Super.QueryRow(ctx, `SELECT count(*) FROM alert_subscriptions WHERE id = $1`, sub).Scan(&n); err != nil {
			t.Fatalf("count subscriptions: %v", err)
		}
		return n
	}

	hidden := func(t *testing.T, path, canary string) {
		t.Helper()
		rec := get(srv, path, out)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusOK {
			t.Fatalf("outsider status = %d, want 404 or an empty 200", rec.Code)
		}
		if strings.Contains(rec.Body.String(), canary) {
			t.Fatalf("outsider saw %q", canary)
		}
	}
	notFound := func(t *testing.T, path string) {
		t.Helper()
		if rec := get(srv, path, out); rec.Code != http.StatusNotFound {
			t.Fatalf("outsider status = %d, want 404", rec.Code)
		}
	}
	shown := func(t *testing.T, path, canary string) {
		t.Helper()
		rec := get(srv, path, owner)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), canary) {
			t.Fatalf("owner status = %d, canary shown = %v; the check cannot fire",
				rec.Code, strings.Contains(rec.Body.String(), canary))
		}
	}
	del := func(path string, hdr map[string]string) int {
		req := httptest.NewRequest(http.MethodDelete, path, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec.Code
	}

	dev := "/devices/" + pk.String()
	cases := map[string]func(t *testing.T){
		"GET /devices": func(t *testing.T) {
			hidden(t, "/devices", devID)
			shown(t, "/devices", devID)
		},
		"GET /devices/{id}": func(t *testing.T) {
			notFound(t, dev)
			shown(t, dev, devID)
		},
		"GET /devices/{id}/telemetry": func(t *testing.T) {
			notFound(t, dev+"/telemetry?metric="+metric)
			shown(t, dev+"/telemetry?metric="+metric, metric)
		},
		"GET /devices/{id}/alerts": func(t *testing.T) {
			notFound(t, dev+"/alerts")
			shown(t, dev+"/alerts", alertText)
		},
		"GET /alerts": func(t *testing.T) {
			hidden(t, "/alerts", alertText)
			shown(t, "/alerts", alertText)
		},
		"GET /alert-subscriptions": func(t *testing.T) {
			hidden(t, "/alert-subscriptions", sub)
			shown(t, "/alert-subscriptions", sub)
		},
		"DELETE /alert-subscriptions/{id}": func(t *testing.T) {
			del("/alert-subscriptions/"+sub, out)
			if subRows() != 1 {
				t.Fatal("outsider deleted tenant A's subscription")
			}
			del("/alert-subscriptions/"+sub, owner)
			if subRows() != 0 {
				t.Fatal("owner delete left the subscription; the check cannot fire")
			}
		},
	}

	for _, route := range apiCrossTenantRoutes {
		run, ok := cases[route]
		if !ok {
			t.Errorf("no cross-tenant case for %q", route)
			continue
		}
		t.Run(route, run)
	}
	for route := range cases {
		if !slices.Contains(apiCrossTenantRoutes, route) {
			t.Errorf("case %q is not in apiCrossTenantRoutes", route)
		}
	}
}
