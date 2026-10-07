package v1_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	apiv1 "thesada.app/app/pkg/api/v1"
	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/ratelimit"
	"thesada.app/app/pkg/service"
)

type rejectSessions struct{}

func (rejectSessions) ValidateSession(string) (*service.Session, error) {
	return nil, errors.New("no session")
}

type bearerUsers struct {
	user *service.User
}

func (b bearerUsers) ValidateToken(tok string) (*service.User, error) {
	if tok == "ok" && b.user != nil {
		return b.user, nil
	}
	return nil, errors.New("no token")
}

func claimSrv(t *testing.T, user *service.User, limit int) http.Handler {
	t.Helper()
	api := apiv1.New(&config.Config{}, &service.Services{}, nil, nil)
	if limit >= 0 {
		api.UseClaimLimiter(ratelimit.New(time.Hour, limit))
	}
	return authmw.APIMiddleware(rejectSessions{}, bearerUsers{user: user}, authmw.APICSRFGuard{}, nil)(api)
}

func postClaim(srv http.Handler, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/devices/claim", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestDeviceClaimAnonymous(t *testing.T) {
	rec := postClaim(claimSrv(t, nil, 5), `{}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: got %d, want 401", rec.Code)
	}
}

func TestDeviceClaimRequiresFields(t *testing.T) {
	user := &service.User{ID: uuid.New(), TenantID: "acme"}
	srv := claimSrv(t, user, 5)
	rec := postClaim(srv, `{}`, "ok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty body: got %d (%s), want 400", rec.Code, rec.Body.String())
	}
	rec = postClaim(srv, `{"device_id":"thesada-aabbccddeeff"}`, "ok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing token: got %d, want 400", rec.Code)
	}
}

func TestDeviceClaimRequiresTenant(t *testing.T) {
	user := &service.User{ID: uuid.New(), TenantID: ""}
	rec := postClaim(claimSrv(t, user, 5), `{"device_id":"d","claim_token":"t"}`, "ok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("no tenant: got %d, want 400", rec.Code)
	}
}

func TestDeviceClaimRateLimit(t *testing.T) {
	user := &service.User{ID: uuid.New(), TenantID: "acme"}
	rec := postClaim(claimSrv(t, user, 0), `{"device_id":"d","claim_token":"secret-token"}`, "ok")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limit: got %d (%s), want 429", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret-token") {
		t.Fatal("rate-limit response echoed the claim token")
	}
}

func TestDeviceClaimRefusesWithoutProvisioner(t *testing.T) {
	user := &service.User{ID: uuid.New(), TenantID: "acme"}
	rec := postClaim(claimSrv(t, user, 5), `{"device_id":"d","claim_token":"secret-token"}`, "ok")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("no provisioner: got %d (%s), want 503", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "secret-token") {
		t.Fatal("refusal echoed the claim token")
	}
}
