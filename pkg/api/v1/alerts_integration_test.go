//go:build integration

// /api/v1 alert + subscription integration tests. Tenant-wide
// alert list, and the subscription CRUD lifecycle (create -> list -> delete)
// through the full gated chain with a real bearer token. Covers validation
// (bad channel 400, foreign device 404) and the gate (anon 401).
//
//	go test -tags integration -run TestAlertHandlers ./pkg/api/v1/...
package v1_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	apiv1 "thesada.app/app/pkg/api/v1"
	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service/servicetest"
)

// del sends a DELETE to srv and returns the recorder.
func del(srv http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodDelete, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestAlertHandlers(t *testing.T) {
	env := servicetest.Start(t)
	srv := authmw.APIMiddleware(env.Services.Auth, env.Services.ApiTokens, authmw.APICSRFGuard{}, nil)(apiv1.New(env.Cfg, env.Services, nil))
	ctx := context.Background()

	const tA, tB = "apialert-a", "apialert-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	user, err := env.Services.Auth.CreateUser(tA, "owner@example.com", "Owner", false)
	if err != nil {
		t.Fatalf("seed user: %v", err)
	}
	token, _, err := env.Services.ApiTokens.IssueToken(tA, user.ID, "test")
	if err != nil {
		t.Fatalf("issue token: %v", err)
	}
	auth := map[string]string{"Authorization": "Bearer " + token}

	devPK, err := env.Services.Devices.Upsert(tA, "dev-001", "S1", "1.0.0", "esp32", "thesada/dev-001")
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if _, err := env.Services.Alerts.InsertAlert(ctx, tA, devPK, "crit", "E9", "fire", nil); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	devB, err := env.Services.Devices.Upsert(tB, "dev-b", "B", "1.0.0", "esp32", "thesada/dev-b")
	if err != nil {
		t.Fatalf("seed foreign device: %v", err)
	}

	// --- alert list ---------------------------------------------------------
	if rec := get(srv, "/alerts", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("anon alerts: got %d, want 401", rec.Code)
	}
	rec := get(srv, "/alerts", auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("alerts: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var alerts []struct {
		DeviceID string `json:"device_id"`
		Severity string `json:"severity"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &alerts); err != nil {
		t.Fatalf("decode alerts: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Severity != "crit" || alerts[0].DeviceID != "dev-001" {
		t.Errorf("alerts = %+v, want one crit on dev-001", alerts)
	}

	// --- subscription create: validation ------------------------------------
	if rec := post(srv, "/alert-subscriptions", `{"channel":"sms"}`, auth); rec.Code != http.StatusBadRequest {
		t.Errorf("bad channel: got %d, want 400", rec.Code)
	}
	if rec := post(srv, "/alert-subscriptions", `{"channel":"email","min_severity":"loud"}`, auth); rec.Code != http.StatusBadRequest {
		t.Errorf("bad severity: got %d, want 400", rec.Code)
	}
	if rec := post(srv, "/alert-subscriptions", `{"channel":"email","device_pk":"`+devB.String()+`"}`, auth); rec.Code != http.StatusNotFound {
		t.Errorf("foreign device sub: got %d, want 404", rec.Code)
	}

	// --- create -> list -> delete -------------------------------------------
	if rec := post(srv, "/alert-subscriptions", `{"channel":"email","min_severity":"warn"}`, auth); rec.Code != http.StatusCreated {
		t.Fatalf("create sub: got %d (%s), want 201", rec.Code, rec.Body.String())
	}
	rec = get(srv, "/alert-subscriptions", auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("list subs: got %d, want 200", rec.Code)
	}
	var subs []struct {
		ID      string `json:"id"`
		Channel string `json:"channel"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &subs); err != nil {
		t.Fatalf("decode subs: %v", err)
	}
	if len(subs) != 1 || subs[0].Channel != "email" {
		t.Fatalf("subs = %+v, want one email sub", subs)
	}

	if rec := del(srv, "/alert-subscriptions/"+subs[0].ID, auth); rec.Code != http.StatusNoContent {
		t.Errorf("delete sub: got %d, want 204", rec.Code)
	}
	rec = get(srv, "/alert-subscriptions", auth)
	var after []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &after)
	if len(after) != 0 {
		t.Errorf("subs after delete = %d, want 0", len(after))
	}
}
