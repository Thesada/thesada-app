//go:build integration

// /api/v1 device-read integration tests. Drives list / get /
// telemetry / alerts through the full chain (APIMiddleware + RequireAuthJSON)
// with a real bearer token: the gate rejects anonymous (401), reads are
// tenant-scoped (a foreign device 404s), and telemetry/alerts return the
// seeded rows.
//
//	go test -tags integration -run TestDeviceReadHandlers ./pkg/api/v1/...
package v1_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	apiv1 "thesada.app/app/pkg/api/v1"
	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service/servicetest"
)

// get sends a GET to srv and returns the recorder.
func get(srv http.Handler, path string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestDeviceReadHandlers(t *testing.T) {
	env := servicetest.Start(t)
	srv := authmw.APIMiddleware(env.Services.Auth, env.Services.ApiTokens, authmw.APICSRFGuard{})(apiv1.New(env.Cfg, env.Services, nil))
	ctx := context.Background()

	const tA, tB = "apidev-a", "apidev-b"
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

	// Seed a device + a telemetry sample + an alert in tenant A.
	devPK, err := env.Services.Devices.Upsert(tA, "dev-001", "Sensor 1", "1.0.0", "esp32", "thesada/dev-001")
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	val := 21.5
	if _, err := env.Services.Telemetry.RecordTelemetry(ctx, tA, devPK, "temp", &val, "", nil); err != nil {
		t.Fatalf("seed telemetry: %v", err)
	}
	if _, err := env.Services.Alerts.InsertAlert(ctx, tA, devPK, "warn", "E1", "too hot", nil); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	// A foreign device in tenant B - must be invisible to tenant A's token.
	devB, err := env.Services.Devices.Upsert(tB, "dev-b", "B", "1.0.0", "esp32", "thesada/dev-b")
	if err != nil {
		t.Fatalf("seed foreign device: %v", err)
	}

	// --- gate: anonymous -> 401 --------------------------------------------
	if rec := get(srv, "/devices", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous list: got %d, want 401", rec.Code)
	}

	// --- list (authed) ------------------------------------------------------
	rec := get(srv, "/devices", auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("list: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var list []struct {
		ID       string `json:"id"`
		DeviceID string `json:"device_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list) != 1 || list[0].DeviceID != "dev-001" {
		t.Errorf("list = %+v, want one device dev-001", list)
	}
	// the redacted shape must never carry the pairing key
	if strings.Contains(rec.Body.String(), "pairing_key") {
		t.Error("device list leaked pairing_key")
	}

	// --- get one ------------------------------------------------------------
	if rec := get(srv, "/devices/"+devPK.String(), auth); rec.Code != http.StatusOK {
		t.Errorf("get: got %d, want 200", rec.Code)
	}
	// foreign device (tenant B) -> 404 under tenant A's token
	if rec := get(srv, "/devices/"+devB.String(), auth); rec.Code != http.StatusNotFound {
		t.Errorf("foreign device: got %d, want 404 (tenant isolation)", rec.Code)
	}
	// malformed id -> 400
	if rec := get(srv, "/devices/not-a-uuid", auth); rec.Code != http.StatusBadRequest {
		t.Errorf("bad id: got %d, want 400", rec.Code)
	}

	// --- telemetry ----------------------------------------------------------
	rec = get(srv, "/devices/"+devPK.String()+"/telemetry", auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("telemetry: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var points []struct {
		Metric   string   `json:"metric"`
		ValueNum *float64 `json:"value_num"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &points); err != nil {
		t.Fatalf("decode telemetry: %v", err)
	}
	if len(points) == 0 || points[0].Metric != "temp" {
		t.Errorf("telemetry = %+v, want a temp point", points)
	}

	// --- alerts -------------------------------------------------------------
	rec = get(srv, "/devices/"+devPK.String()+"/alerts", auth)
	if rec.Code != http.StatusOK {
		t.Fatalf("alerts: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var alerts []struct {
		Severity string `json:"severity"`
		Message  string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &alerts); err != nil {
		t.Fatalf("decode alerts: %v", err)
	}
	if len(alerts) != 1 || alerts[0].Severity != "warn" {
		t.Errorf("alerts = %+v, want one warn", alerts)
	}
}
