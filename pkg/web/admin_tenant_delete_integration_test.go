//go:build integration

// Tenant delete against a real DB: every device goes through the device
// delete path first, so its serials answer revoked, its enrollment rows are
// gone and its broker client was torn down (or the failure is on record).
//
//	go test -tags integration -run TestAdminTenantDelete ./pkg/web/...
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
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

const (
	tdHome   = "td-home"
	tdGone   = "td-gone"
	tdDevID  = "thesada-0a0b0c0d0e0f"
	tdPub    = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
	tdSerial = "ab12"
)

// tdFixture is a super-admin session in tdHome and one paired, enrolled
// device in tdGone.
type tdFixture struct {
	env    *servicetest.Env
	s      *Server
	token  string
	device uuid.UUID
}

// seedTenantDelete seeds both tenants, the operator, and the device.
// in: t. out: fixture.
func seedTenantDelete(t *testing.T) tdFixture {
	t.Helper()
	env := servicetest.Start(t)
	ctx := context.Background()
	env.SeedTenant(t, tdHome)
	env.SeedTenant(t, tdGone)
	u, err := env.Services.Auth.CreateUser(tdHome, "op@example.com", "op@example.com", false)
	if err != nil {
		t.Fatalf("seed operator: %v", err)
	}
	if _, err := env.Super.Exec(ctx, `UPDATE users SET is_super_admin = true WHERE id = $1`, u.ID); err != nil {
		t.Fatalf("grant super-admin: %v", err)
	}
	tok, _, err := env.Services.Auth.CreateSession(tdHome, u.ID, "magic_link", "go-test", "127.0.0.1")
	if err != nil {
		t.Fatalf("session: %v", err)
	}
	pk, err := env.Services.Devices.Upsert(tdGone, tdDevID, "", "", "", "thesada/"+tdGone+"/"+tdDevID)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	now := time.Now()
	if err := env.Services.Certificates.IssueWithIdentity(ctx, tdGone, pk, tdSerial, "cn",
		now.Add(-time.Hour), now.Add(time.Hour), "pem", tdPub); err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	// One sealed row claimed by the tenant, one unclaimed row under the same id.
	if _, err := env.Super.Exec(ctx,
		`INSERT INTO device_enrollments (device_id, pubkey_hex, claim_token_hash, verified_at, claimed_by_tenant, claimed_at, cert_delivered_at)
		 VALUES ($1, $2, 'x', now(), $3, now(), now()),
		        ($1, $4, 'y', now(), NULL, NULL, NULL)`,
		tdDevID, tdPub, tdGone, strings.Repeat("e", 64)); err != nil {
		t.Fatalf("seed enrollment: %v", err)
	}
	// A disconnected broker client: every dynsec call fails fast.
	s := &Server{cfg: env.Cfg, services: env.Services, mqtt: &mqtt.Client{}, jobs: newRequestStore[jobResult](time.Minute)}
	s.parseTemplates()
	return tdFixture{env: env, s: s, token: tok, device: pk}
}

// postTenantDelete runs POST /admin/tenants/{slug}/delete as the operator
// and follows the job it starts.
// in: t, fixture, form. out: where the finished job sends the operator.
func postTenantDelete(t *testing.T, f tdFixture, form url.Values) string {
	t.Helper()
	return followJob(t, f, serveAsOperator(t, f, http.MethodPost, f.s.handleAdminTenantDelete, "slug", tdGone, form))
}

// serveAsOperator runs one admin handler behind the session middleware.
// in: t, fixture, method, handler, path value name and value, form. out: recorder.
func serveAsOperator(t *testing.T, f tdFixture, method string, h http.HandlerFunc, key, val string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if key != "" {
		req.SetPathValue(key, val)
	}
	req.AddCookie(&http.Cookie{Name: authmw.CookieName, Value: f.token})
	rec := httptest.NewRecorder()
	authmw.Middleware(f.s.services.Auth, nil)(authmw.RequireAuth(h)).ServeHTTP(rec, req)
	return rec
}

// brokerFlagged counts device.delete audit rows for the fixture device that
// carry broker_teardown_failed.
// in: t, fixture. out: count.
func brokerFlagged(t *testing.T, f tdFixture) int {
	t.Helper()
	return count(t, f, `SELECT count(*) FROM admin_audit
		WHERE action = 'device.delete' AND target_id = $1
		  AND detail->>'broker_teardown_failed' = 'true'`, f.device.String())
}

// followJob checks a delete answered with the job page at once, then polls
// that page until it redirects.
// in: t, fixture, the POST's recorder. out: the final redirect target.
func followJob(t *testing.T, f tdFixture, rec *httptest.ResponseRecorder) string {
	t.Helper()
	loc := rec.Header().Get("Location")
	id, ok := strings.CutPrefix(loc, "/admin/jobs/")
	if rec.Code != http.StatusFound || !ok {
		t.Fatalf("delete answered %d %q, want a redirect to the job page", rec.Code, loc)
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		poll := serveAsOperator(t, f, http.MethodGet, f.s.handleAdminJob, "id", id, nil)
		switch poll.Code {
		case http.StatusFound:
			return poll.Header().Get("Location")
		case http.StatusOK:
			time.Sleep(100 * time.Millisecond)
		default:
			t.Fatalf("job page answered %d", poll.Code)
		}
	}
	t.Fatal("job did not finish in 60s")
	return ""
}

// count runs a count(*) query on the superuser pool.
// in: t, fixture, query, args. out: count.
func count(t *testing.T, f tdFixture, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.env.Super.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestAdminTenantDelete_WalksDevicesThroughDeviceDelete(t *testing.T) {
	f := seedTenantDelete(t)
	ctx := context.Background()

	loc := postTenantDelete(t, f, url.Values{"accept_serial_recovery": {"true"}})

	if n := count(t, f, `SELECT count(*) FROM tenants WHERE id = $1`, tdGone); n != 0 {
		t.Fatalf("tenant survived, job sent the operator to %q", loc)
	}
	got, _, err := f.env.Services.Certificates.RevocationStatus(ctx, tdDevID, tdPub, tdSerial)
	if err != nil || got != service.EnrollStatusRevoked {
		t.Fatalf("status for the deleted serial = %q err %v, want revoked", got, err)
	}
	if n := count(t, f, `SELECT count(*) FROM device_enrollments WHERE device_id = $1`, tdDevID); n != 0 {
		t.Fatalf("enrollment rows left = %d, want 0", n)
	}
	if n := count(t, f, `SELECT count(*) FROM admin_audit WHERE action = 'device.delete' AND target_id = $1`,
		f.device.String()); n != 1 {
		t.Fatalf("device.delete audit rows = %d, want 1", n)
	}
	// The broker is unreachable, so the teardown ran and failed: the device row
	// carries it, the tenant row does not repeat it.
	if n := brokerFlagged(t, f); n != 1 {
		t.Fatalf("device.delete audit rows flagging the live broker client = %d, want 1", n)
	}
	if n := count(t, f, `SELECT count(*) FROM admin_audit
		WHERE action = 'tenant.delete' AND detail ? 'broker_teardown_failed'`); n != 0 {
		t.Fatalf("tenant.delete audit repeats the broker failure, rows = %d", n)
	}
	if !strings.Contains(loc, flashTenantIncomplete.query()) {
		t.Fatalf("operator not told about the broker teardown failure, sent to %q", loc)
	}
}

func TestAdminTenantDelete_RefusedDeviceKeepsTheTenant(t *testing.T) {
	f := seedTenantDelete(t)
	ctx := context.Background()

	// Paired device, no usable recovery path, no override: the gate refuses.
	if loc := postTenantDelete(t, f, url.Values{}); !strings.Contains(loc, flashTenantKept.query()) {
		t.Fatalf("operator not told the tenant was kept, sent to %q", loc)
	}

	if n := count(t, f, `SELECT count(*) FROM tenants WHERE id = $1`, tdGone); n != 1 {
		t.Fatal("tenant deleted although a device was refused")
	}
	if n := count(t, f, `SELECT count(*) FROM devices WHERE id = $1`, f.device); n != 1 {
		t.Fatal("refused device was cascaded away")
	}
	got, _, err := f.env.Services.Certificates.RevocationStatus(ctx, tdDevID, tdPub, tdSerial)
	if err != nil || got != service.EnrollStatusActive {
		t.Fatalf("refused device status = %q err %v, want active", got, err)
	}
}

// The per-device alert cascades away with the row, so single and bulk delete
// record a failed broker teardown on the device.delete audit row and say so.
func TestAdminDeviceDelete_BrokerTeardownFailureOutlivesTheDevice(t *testing.T) {
	cases := []struct {
		name string
		post func(f tdFixture) string
	}{
		{"single", func(f tdFixture) string {
			return serveAsOperator(t, f, http.MethodPost, f.s.handleAdminDeviceDelete, "id", f.device.String(), url.Values{
				"confirm_device_id": {tdDevID}, "accept_serial_recovery": {"true"}}).Header().Get("Location")
		}},
		{"bulk", func(f tdFixture) string {
			return followJob(t, f, serveAsOperator(t, f, http.MethodPost, f.s.handleAdminDevicesBulk, "", "", url.Values{
				"action": {"delete"}, "device_ids": {f.device.String()}, "accept_serial_recovery": {"true"}}))
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := seedTenantDelete(t)
			loc := c.post(f)
			if n := count(t, f, `SELECT count(*) FROM devices WHERE id = $1`, f.device); n != 0 {
				t.Fatalf("device survived, sent to %q", loc)
			}
			if n := brokerFlagged(t, f); n != 1 {
				t.Fatalf("device.delete audit rows flagging the live broker client = %d, want 1", n)
			}
			if !strings.Contains(loc, flashAdminBrokerLive.query()) {
				t.Fatalf("redirect %q does not carry the broker flash", loc)
			}
		})
	}
}

// Bulk delete answers with the job page before the cascade runs, and the
// finished job lands on the device list with the outcome.
func TestAdminBulkDelete_RunsAsAJob(t *testing.T) {
	f := seedTenantDelete(t)
	loc := followJob(t, f, serveAsOperator(t, f, http.MethodPost, f.s.handleAdminDevicesBulk, "", "", url.Values{
		"action": {"delete"}, "device_ids": {f.device.String()}, "accept_serial_recovery": {"true"}}))
	if !strings.HasPrefix(loc, flashAdminBulkDeleted.on("/admin/devices")) {
		t.Fatalf("finished job sent the operator to %q, want the bulk_deleted flash", loc)
	}
	if n := count(t, f, `SELECT count(*) FROM devices WHERE id = $1`, f.device); n != 0 {
		t.Fatal("device survived the bulk delete job")
	}
}

// runTenantDelete posts a tenant delete for slug and, if it started a job,
// waits for that job to stop answering 200.
// in: t, fixture, slug. out: the POST's recorder.
func runTenantDelete(t *testing.T, f tdFixture, slug string) *httptest.ResponseRecorder {
	t.Helper()
	rec := serveAsOperator(t, f, http.MethodPost, f.s.handleAdminTenantDelete, "slug", slug,
		url.Values{"accept_serial_recovery": {"true"}})
	id, ok := strings.CutPrefix(rec.Header().Get("Location"), "/admin/jobs/")
	if !ok {
		return rec
	}
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if serveAsOperator(t, f, http.MethodGet, f.s.handleAdminJob, "id", id, nil).Code != http.StatusOK {
			return rec
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("job did not finish in 60s")
	return rec
}

// The users FK cascades, so a tenant that homes a super-admin is never deleted:
// not the operator's own home while impersonating, not anyone else's.
func TestAdminTenantDelete_KeepsSuperAdminTenants(t *testing.T) {
	t.Run("own_home_while_impersonating", func(t *testing.T) {
		f := seedTenantDelete(t)
		sess, err := f.env.Services.Auth.ValidateSession(f.token)
		if err != nil {
			t.Fatal(err)
		}
		if err := f.env.Services.Auth.SetImpersonation(sess.ID, tdGone); err != nil {
			t.Fatal(err)
		}
		rec := runTenantDelete(t, f, tdHome)
		if n := count(t, f, `SELECT count(*) FROM tenants WHERE id = $1`, tdHome); n != 1 {
			t.Fatalf("operator's home tenant deleted (answer %d %q)", rec.Code, rec.Header().Get("Location"))
		}
		if n := count(t, f, `SELECT count(*) FROM users WHERE tenant_id = $1 AND is_super_admin`, tdHome); n != 1 {
			t.Fatalf("super-admin rows in home = %d, want 1", n)
		}
	})
	t.Run("other_tenant_with_super_admin", func(t *testing.T) {
		f := seedTenantDelete(t)
		ctx := context.Background()
		u, err := f.env.Services.Auth.CreateUser(tdGone, "su2@example.com", "su2@example.com", false)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.env.Super.Exec(ctx, `UPDATE users SET is_super_admin = true WHERE id = $1`, u.ID); err != nil {
			t.Fatal(err)
		}
		rec := runTenantDelete(t, f, tdGone)
		if n := count(t, f, `SELECT count(*) FROM users WHERE id = $1`, u.ID); n != 1 {
			t.Fatalf("super-admin in %s deleted (answer %d %q)", tdGone, rec.Code, rec.Header().Get("Location"))
		}
		if n := count(t, f, `SELECT count(*) FROM devices WHERE id = $1`, f.device); n != 1 {
			t.Fatal("device walk ran for a tenant that cannot be deleted")
		}
		if !strings.Contains(rec.Body.String(), "super-admin account") {
			t.Fatalf("refusal not shown, answer %d %q", rec.Code, rec.Header().Get("Location"))
		}
	})
}
