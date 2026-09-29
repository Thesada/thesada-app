//go:build integration

// Owner revoke through the session middleware against a real DB and broker:
// tenant scope, the stale-owner refusal, the ownerless refusal, and the
// success path's order (enrollment reopened, cert.clear delivered).
//
//	go test -tags integration -run TestOwnerRevoke ./pkg/web/...
package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
)

const (
	holderTenant   = "rv-holder"
	claimantTenant = "rv-claimant"
	revokeDevID    = "thesada-0123456789ab"
	revokePrefix   = "thesada/" + holderTenant + "/" + revokeDevID
	// holderPub is the unit the holder tenant claimed; rivalPub is a second
	// key announcing the same device id (a squatter, or the unit re-keyed
	// and claimed by the claimant tenant).
	holderPub = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	rivalPub  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// revokeFixture is one owned, paired device plus session tokens for the users
// that act on it: owner, member and admin in the holder tenant, outsider in
// the claimant tenant.
type revokeFixture struct {
	env                            *servicetest.Env
	device                         uuid.UUID
	owner, member, admin, outsider string
}

// seedRevokeFixture seeds both tenants, four users, and an owned paired device.
// in: t, env. out: fixture with session tokens.
func seedRevokeFixture(t *testing.T, env *servicetest.Env) revokeFixture {
	t.Helper()
	ctx := context.Background()
	env.SeedTenant(t, holderTenant)
	env.SeedTenant(t, claimantTenant)
	session := func(tenant, email string, super bool) (uuid.UUID, string) {
		u, err := env.Services.Auth.CreateUser(tenant, email, email, false)
		if err != nil {
			t.Fatalf("seed user %s: %v", email, err)
		}
		if super {
			if _, err := env.Super.Exec(ctx, `UPDATE users SET is_super_admin = true WHERE id = $1`, u.ID); err != nil {
				t.Fatalf("grant super-admin: %v", err)
			}
		}
		tok, _, err := env.Services.Auth.CreateSession(tenant, u.ID, "magic_link", "go-test", "127.0.0.1")
		if err != nil {
			t.Fatalf("session %s: %v", email, err)
		}
		return u.ID, tok
	}
	ownerID, ownerTok := session(holderTenant, "owner@example.com", false)
	_, memberTok := session(holderTenant, "member@example.com", false)
	_, adminTok := session(holderTenant, "admin@example.com", true)
	_, outsiderTok := session(claimantTenant, "outsider@example.com", false)

	pk, err := env.Services.Devices.Upsert(holderTenant, revokeDevID, "", "", "", revokePrefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	if _, err := env.Super.Exec(ctx, `UPDATE devices SET owner_user_id = $1 WHERE id = $2`, ownerID, pk); err != nil {
		t.Fatalf("set owner: %v", err)
	}
	now := time.Now()
	if err := env.Services.Certificates.Issue(ctx, holderTenant, pk, "rv-serial", "rv-cn",
		now, now.Add(time.Hour), "pem"); err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	return revokeFixture{env: env, device: pk, owner: ownerTok, member: memberTok, admin: adminTok, outsider: outsiderTok}
}

// seedEnrollment inserts one verified enrollment row for the fixture device.
// in: t, env, pubkey, claiming tenant ("" leaves it unclaimed). out: none.
func seedEnrollment(t *testing.T, env *servicetest.Env, pub, tenant string) {
	t.Helper()
	var claimed any
	if tenant != "" {
		claimed = tenant
	}
	if _, err := env.Super.Exec(context.Background(),
		`INSERT INTO device_enrollments (device_id, pubkey_hex, claim_token_hash, verified_at, claimed_by_tenant, claimed_at)
		 VALUES ($1, $2, 'x', now(), $3, CASE WHEN $3::text IS NULL THEN NULL ELSE now() END)`,
		revokeDevID, pub, claimed); err != nil {
		t.Fatalf("seed enrollment: %v", err)
	}
}

// enrollmentRows counts every enrollment row for the fixture device.
// in: t, env. out: row count.
func enrollmentRows(t *testing.T, env *servicetest.Env) int {
	t.Helper()
	var n int
	if err := env.Super.QueryRow(context.Background(),
		`SELECT count(*) FROM device_enrollments WHERE device_id = $1`, revokeDevID).Scan(&n); err != nil {
		t.Fatalf("count enrollments: %v", err)
	}
	return n
}

// postRevoke runs POST /devices/{id}/revoke through the session middleware.
// in: t, server, session token, device pk, typed confirmation. out: recorder.
func postRevoke(t *testing.T, s *Server, token string, pk uuid.UUID, confirm string) *httptest.ResponseRecorder {
	t.Helper()
	form := url.Values{"confirm_device_id": {confirm}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/devices/"+pk.String()+"/revoke", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", pk.String())
	req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: token})
	rec := httptest.NewRecorder()
	authmw.Middleware(s.services.Auth, nil)(authmw.RequireAuth(s.handleDeviceRevoke)).ServeHTTP(rec, req)
	return rec
}

// wantFlash fails the test unless the response redirects with flash.
// in: t, recorder, expected flash. out: none.
func wantFlash(t *testing.T, rec *httptest.ResponseRecorder, flash deviceFlashCode) {
	t.Helper()
	if loc := rec.Header().Get("Location"); !strings.HasSuffix(loc, flash.on("")) {
		t.Fatalf("Location = %q, want %s=%s", loc, flash.key, flash.code)
	}
}

// stillPaired reports whether the fixture device keeps its live cert.
// in: t, fixture. out: paired.
func stillPaired(t *testing.T, f revokeFixture) bool {
	t.Helper()
	d, err := f.env.Services.Devices.GetByIDAny(context.Background(), f.device)
	if err != nil || d == nil {
		t.Fatalf("reload device: %v", err)
	}
	return d.PairedAt != nil
}

func TestOwnerRevoke_RefusalsLeaveTheDeviceUntouched(t *testing.T) {
	env := servicetest.Start(t)
	f := seedRevokeFixture(t, env)
	s := &Server{cfg: env.Cfg, services: env.Services}

	t.Run("tenant member who is not the owner gets 404", func(t *testing.T) {
		if rec := postRevoke(t, s, f.member, f.device, revokeDevID); rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		if !stillPaired(t, f) {
			t.Fatal("a refused revoke must not touch the cert")
		}
	})

	t.Run("user of another tenant gets 404", func(t *testing.T) {
		if rec := postRevoke(t, s, f.outsider, f.device, revokeDevID); rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		if !stillPaired(t, f) {
			t.Fatal("a cross-tenant revoke must not touch the cert")
		}
	})

	t.Run("wrong typed confirmation changes nothing", func(t *testing.T) {
		wantFlash(t, postRevoke(t, s, f.owner, f.device, "thesada-000000000000"), flashConfirmDeviceID)
		if !stillPaired(t, f) {
			t.Fatal("an unconfirmed revoke must not touch the cert")
		}
	})

	t.Run("old owner cannot revoke once another tenant claimed the unit", func(t *testing.T) {
		seedEnrollment(t, env, rivalPub, claimantTenant)
		t.Cleanup(func() { env.Truncate(t, "device_enrollments") })
		wantFlash(t, postRevoke(t, s, f.owner, f.device, revokeDevID), flashRevokeNotHeld)
		if n := enrollmentRows(t, env); n != 1 {
			t.Fatalf("the other tenant's enrollment must survive, rows = %d", n)
		}
		if !stillPaired(t, f) {
			t.Fatal("a stale owner's revoke must not touch the cert")
		}
	})

	t.Run("super-admin is sent to the admin path for an ownerless device", func(t *testing.T) {
		if _, err := env.Super.Exec(context.Background(),
			`UPDATE devices SET owner_user_id = NULL WHERE id = $1`, f.device); err != nil {
			t.Fatalf("clear owner: %v", err)
		}
		wantFlash(t, postRevoke(t, s, f.admin, f.device, revokeDevID), flashRevokeNoOwner)
		if !stillPaired(t, f) {
			t.Fatal("an ownerless device must not be revoked here")
		}
	})
}

func TestOwnerRevoke_ReopensEnrollmentAndDeliversCertClear(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	f := seedRevokeFixture(t, env)
	seedEnrollment(t, env, holderPub, holderTenant)
	seedEnrollment(t, env, rivalPub, "")

	fd := mqtttest.NewFakeDevice(t, broker, revokePrefix)
	fd.Handle("cert.clear", func(string, []byte) []mqtttest.Response {
		return mqtttest.OK("cleared")
	})

	wantFlash(t, postRevoke(t, s, f.owner, f.device, revokeDevID), flashRevoked)
	if stillPaired(t, f) {
		t.Fatal("the device must no longer read as paired")
	}
	if n := enrollmentRows(t, env); n != 0 {
		t.Fatalf("every enrollment row must be reset for a fresh cycle, rows = %d", n)
	}
	if fd.Calls("cert.clear") != 1 {
		t.Fatalf("cert.clear calls = %d, want 1", fd.Calls("cert.clear"))
	}
	if cert, err := env.Services.Certificates.GetActive(context.Background(), holderTenant, f.device); err != nil || cert != nil {
		t.Fatalf("active cert after revoke = %+v err=%v, want none", cert, err)
	}

	wantFlash(t, postRevoke(t, s, f.owner, f.device, revokeDevID), flashRevokeAlready)
	if fd.Calls("cert.clear") != 1 {
		t.Fatalf("a re-post must not send cert.clear again, calls = %d", fd.Calls("cert.clear"))
	}
}

func TestOwnerRevoke_WithoutATopicSaysTheDeviceWasNotTold(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	f := seedRevokeFixture(t, env)
	seedEnrollment(t, env, holderPub, holderTenant)
	if _, err := env.Super.Exec(context.Background(),
		`UPDATE devices SET mqtt_topic_prefix = NULL WHERE id = $1`, f.device); err != nil {
		t.Fatalf("clear topic prefix: %v", err)
	}

	wantFlash(t, postRevoke(t, s, f.owner, f.device, revokeDevID), flashRevokeUnsent)
	if stillPaired(t, f) {
		t.Fatal("the revoke itself must still go through")
	}
	if n := enrollmentRows(t, env); n != 0 {
		t.Fatalf("enrollment must still be reopened, rows = %d", n)
	}
}
