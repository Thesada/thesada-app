//go:build integration

// /api/v1 device-pair integration tests. POST /devices/{id}/pair
// is the only route guarded by RequireSuperAdminJSON, so it is the one place the
// 403 super-admin gate is exercised end-to-end. Drives the full gated chain with
// real bearer tokens: anon 401, a normal authed user 403, and a super-admin
// happy-path certificate issue (200) plus the handler's own bad-id 400 and
// unknown-device 404 once past the gate.
//
//	go test -tags integration -run TestDevicePairHandler ./pkg/api/v1/...
package v1_test

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"

	apiv1 "thesada.app/app/pkg/api/v1"
	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/pki"
	"thesada.app/app/pkg/service/servicetest"
)

// TestDevicePairHandler exercises the super-admin-gated pair route.
//
// in:  a migrated testcontainer env, a real CA (so the happy path can sign),
//
//	one seeded device, plus a normal user and a promoted super-admin.
//
// out: asserts the gate (401 anon / 403 normal) and, past the gate, bad-id 400,
//
//	unknown-device 404, and a 200 issue whose payload carries the expected CN
//	and non-empty cert / key / CA PEM.
func TestDevicePairHandler(t *testing.T) {
	env := servicetest.Start(t)

	// Real CA: the read/alert suites pass nil because their routes never reach
	// the signer; pair does, so a nil CA would 503 before the handler logic.
	ca, _, err := pki.Bootstrap(t.TempDir(), "test-passphrase")
	if err != nil {
		t.Fatalf("bootstrap CA: %v", err)
	}
	srv := authmw.APIMiddleware(env.Services.Auth, env.Services.ApiTokens, authmw.APICSRFGuard{})(apiv1.New(env.Cfg, env.Services, ca))

	const tenant = "apipair-a"
	env.SeedTenant(t, tenant)

	devPK, err := env.Services.Devices.Upsert(tenant, "dev-001", "Sensor 1", "1.0.0", "esp32", "thesada/dev-001")
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	path := "/devices/" + devPK.String() + "/pair"

	// Normal user: clears auth, must be stopped by the super-admin gate (403).
	normal, err := env.Services.Auth.CreateUser(tenant, "user@example.com", "User", false)
	if err != nil {
		t.Fatalf("seed normal user: %v", err)
	}
	normalTok, _, err := env.Services.ApiTokens.IssueToken(tenant, normal.ID, "normal")
	if err != nil {
		t.Fatalf("issue normal token: %v", err)
	}
	normalAuth := map[string]string{"Authorization": "Bearer " + normalTok}

	// Super-admin: promoted before the token is issued so the gate lets it past.
	admin, err := env.Services.Auth.CreateUser(tenant, "admin@example.com", "Admin", false)
	if err != nil {
		t.Fatalf("seed admin user: %v", err)
	}
	if err := env.Services.Auth.PromoteSuperAdmin(admin.ID); err != nil {
		t.Fatalf("promote super-admin: %v", err)
	}
	adminTok, _, err := env.Services.ApiTokens.IssueToken(tenant, admin.ID, "admin")
	if err != nil {
		t.Fatalf("issue admin token: %v", err)
	}
	adminAuth := map[string]string{"Authorization": "Bearer " + adminTok}

	// --- gate: anon 401, normal user 403 ------------------------------------
	if rec := post(srv, path, "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("anon pair: got %d, want 401", rec.Code)
	}
	if rec := post(srv, path, "", normalAuth); rec.Code != http.StatusForbidden {
		t.Errorf("non-super-admin pair: got %d, want 403", rec.Code)
	}

	// --- past the gate: bad id 400, unknown device 404 ----------------------
	if rec := post(srv, "/devices/not-a-uuid/pair", "", adminAuth); rec.Code != http.StatusBadRequest {
		t.Errorf("bad device id: got %d, want 400", rec.Code)
	}
	if rec := post(srv, "/devices/"+uuid.NewString()+"/pair", "", adminAuth); rec.Code != http.StatusNotFound {
		t.Errorf("unknown device: got %d, want 404", rec.Code)
	}

	// --- happy path: super-admin issues a cert ------------------------------
	rec := post(srv, path, "", adminAuth)
	if rec.Code != http.StatusOK {
		t.Fatalf("pair issue: got %d (%s), want 200", rec.Code, rec.Body.String())
	}
	var resp struct {
		CN         string `json:"cn"`
		SerialHex  string `json:"serial_hex"`
		CertPEM    string `json:"cert_pem"`
		PrivateKey string `json:"private_key_pem"`
		CAPEM      string `json:"ca_pem"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode pair response: %v", err)
	}
	if want := "thesada-" + tenant + "-dev-001"; resp.CN != want {
		t.Errorf("CN = %q, want %q", resp.CN, want)
	}
	if resp.SerialHex == "" || resp.CertPEM == "" || resp.PrivateKey == "" || resp.CAPEM == "" {
		t.Errorf("pair response has empty field(s): serial=%q certLen=%d keyLen=%d caLen=%d",
			resp.SerialHex, len(resp.CertPEM), len(resp.PrivateKey), len(resp.CAPEM))
	}
}
