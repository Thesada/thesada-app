//go:build integration

// JSON claim against a real database. The unit tests stop at the gate.
// This one walks announce, verify, and POST /devices/claim, then checks
// the devices row the handler is responsible for writing.
//
//	go test -tags integration -run TestDeviceClaimJSON ./pkg/api/v1/...
package v1_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	apiv1 "thesada.app/app/pkg/api/v1"
	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service/servicetest"
)

func claimJSON(srv http.Handler, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/devices/claim", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func announceVerified(t *testing.T, env *servicetest.Env, deviceID, token string) string {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	ctx := context.Background()
	challenge, err := env.Services.Enrollments.Announce(ctx, deviceID, pubHex, token)
	if err != nil {
		t.Fatalf("announce: %v", err)
	}
	if err := env.Services.Enrollments.Verify(ctx, deviceID, pubHex, ed25519.Sign(priv, []byte(challenge))); err != nil {
		t.Fatalf("verify: %v", err)
	}
	return pubHex
}

func TestDeviceClaimJSON(t *testing.T) {
	env := servicetest.Start(t)
	api := apiv1.New(env.Cfg, env.Services, nil, nil)
	var provisioned []string
	var provisionErr error
	api.SetClaimProvisioner(func(_ context.Context, _, deviceID, _, _ string) (string, error) {
		provisioned = append(provisioned, deviceID)
		if provisionErr != nil {
			return "dynsec", provisionErr
		}
		return "", nil
	})
	srv := authmw.APIMiddleware(env.Services.Auth, env.Services.ApiTokens, authmw.APICSRFGuard{}, nil)(api)

	const tenant = "claim-json"
	env.SeedTenant(t, tenant)
	user, err := env.Services.Auth.CreateUser(tenant, "owner@claim-json.test", "Owner", false)
	if err != nil {
		t.Fatalf("user: %v", err)
	}
	token, _, err := env.Services.ApiTokens.IssueToken(tenant, user.ID, "claim")
	if err != nil {
		t.Fatalf("token: %v", err)
	}

	const deviceID = "thesada-aabbccddee01"
	const claimToken = "claim-token-json"
	announceVerified(t, env, deviceID, claimToken)

	rec := claimJSON(srv, `{"device_id":"`+deviceID+`","claim_token":"`+claimToken+`"}`, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("claim: got %d %s", rec.Code, rec.Body.String())
	}
	var body struct {
		DeviceID string    `json:"device_id"`
		ID       uuid.UUID `json:"id"`
		Status   string    `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.DeviceID != deviceID || body.Status != "claimed" || body.ID == uuid.Nil {
		t.Fatalf("body = %+v", body)
	}
	if len(provisioned) != 1 || provisioned[0] != deviceID {
		t.Fatalf("provisioned = %v", provisioned)
	}
	var owner uuid.UUID
	if err := env.Super.QueryRow(context.Background(),
		`SELECT owner_user_id FROM devices WHERE id = $1 AND tenant_id = $2`,
		body.ID, tenant).Scan(&owner); err != nil {
		t.Fatalf("device row: %v", err)
	}
	if owner != user.ID {
		t.Fatalf("owner = %s, want %s", owner, user.ID)
	}

	provisionErr = errors.New("broker down")
	const deviceID2 = "thesada-aabbccddee02"
	announceVerified(t, env, deviceID2, claimToken)
	rec = claimJSON(srv, `{"device_id":"`+deviceID2+`","claim_token":"`+claimToken+`"}`, token)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("dynsec: got %d %s", rec.Code, rec.Body.String())
	}
	var still int
	if err := env.Super.QueryRow(context.Background(),
		`SELECT count(*) FROM devices WHERE tenant_id = $1 AND device_id = $2 AND owner_user_id = $3`,
		tenant, deviceID2, user.ID).Scan(&still); err != nil {
		t.Fatal(err)
	}
	if still != 1 {
		t.Fatalf("claimed row after broker failure = %d, want 1", still)
	}
}
