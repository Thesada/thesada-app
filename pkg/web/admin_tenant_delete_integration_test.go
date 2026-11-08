//go:build integration

// Tenant delete against a real DB: every device goes through the device
// delete path first, so its serials answer revoked, its enrollment rows are
// gone and its broker client was torn down (or the failure is on record).
//
//	go test -tags integration -run TestAdminTenantDelete ./pkg/web/...
package web

import (
	"context"
	"errors"
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
	s := &Server{cfg: env.Cfg, services: env.Services, mqtt: &mqtt.Client{}, jobs: newRequestStore[jobResult](time.Minute, t.Context().Done())}
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

// seedOtherClaim gives a second tenant its own device row, a cert for its key
// and a sealed claim on tdDevID, which device_id's per-tenant uniqueness allows.
// in: t, fixture. out: the other tenant.
func seedOtherClaim(t *testing.T, f tdFixture) string {
	t.Helper()
	const other = "td-other"
	f.env.SeedTenant(t, other)
	pk, err := f.env.Services.Devices.Upsert(other, tdDevID, "", "", "", "thesada/"+other+"/"+tdDevID)
	if err != nil {
		t.Fatalf("seed other device: %v", err)
	}
	now := time.Now()
	if err := f.env.Services.Certificates.IssueWithIdentity(context.Background(), other, pk, "ef01", "cn-other",
		now.Add(-time.Hour), now.Add(time.Hour), "pem", strings.Repeat("f", 64)); err != nil {
		t.Fatalf("issue other cert: %v", err)
	}
	if _, err := f.env.Super.Exec(context.Background(),
		`INSERT INTO device_enrollments (device_id, pubkey_hex, claim_token_hash, verified_at, claimed_by_tenant, claimed_at, cert_delivered_at)
		 VALUES ($1, $2, 'z', now(), $3, now(), now())`, tdDevID, strings.Repeat("f", 64), other); err != nil {
		t.Fatalf("seed other claim: %v", err)
	}
	return other
}

// Every admin path that resets enrollment clears the acting device's rows and
// keeps the claim another tenant holds on the same device_id.
func TestAdminDelete_KeepsAnotherTenantsClaim(t *testing.T) {
	cases := []struct {
		name string
		run  func(f tdFixture)
	}{
		{"single", func(f tdFixture) {
			serveAsOperator(t, f, http.MethodPost, f.s.handleAdminDeviceDelete, "id", f.device.String(), url.Values{
				"confirm_device_id": {tdDevID}, "accept_serial_recovery": {"true"}})
		}},
		{"bulk", func(f tdFixture) {
			followJob(t, f, serveAsOperator(t, f, http.MethodPost, f.s.handleAdminDevicesBulk, "", "", url.Values{
				"action": {"delete"}, "device_ids": {f.device.String()}, "accept_serial_recovery": {"true"}}))
		}},
		{"tenant", func(f tdFixture) { postTenantDelete(t, f, url.Values{"accept_serial_recovery": {"true"}}) }},
		{"revoke", func(f tdFixture) {
			serveAsOperator(t, f, http.MethodPost, f.s.handleAdminDevicePairRevoke, "id", f.device.String(), url.Values{
				"accept_serial_recovery": {"true"}})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := seedTenantDelete(t)
			other := seedOtherClaim(t, f)
			c.run(f)
			if n := count(t, f, `SELECT count(*) FROM device_enrollments
				WHERE device_id = $1 AND claimed_by_tenant IS DISTINCT FROM $2`, tdDevID, other); n != 0 {
				t.Fatalf("acting tenant's enrollment rows left = %d, want 0", n)
			}
			if n := count(t, f, `SELECT count(*) FROM device_enrollments
				WHERE device_id = $1 AND claimed_by_tenant = $2`, tdDevID, other); n != 1 {
				t.Fatalf("other tenant's claim rows = %d, want 1", n)
			}
		})
	}
}

// A claim the reassign left on the old tenant is the device's own, sealed or
// pending. Deleting or revoking the device in its new tenant clears it.
func TestAdminDelete_ClearsClaimLeftByReassign(t *testing.T) {
	paths := []struct {
		name string
		run  func(f tdFixture)
	}{
		{"delete", func(f tdFixture) {
			serveAsOperator(t, f, http.MethodPost, f.s.handleAdminDeviceDelete, "id", f.device.String(), url.Values{
				"confirm_device_id": {tdDevID}, "accept_serial_recovery": {"true"}})
		}},
		{"revoke", func(f tdFixture) {
			serveAsOperator(t, f, http.MethodPost, f.s.handleAdminDevicePairRevoke, "id", f.device.String(), url.Values{
				"accept_serial_recovery": {"true"}})
		}},
	}
	for _, sealed := range []bool{true, false} {
		for _, p := range paths {
			name := p.name + "_pending"
			if sealed {
				name = p.name + "_sealed"
			}
			t.Run(name, func(t *testing.T) {
				f := seedTenantDelete(t)
				if !sealed {
					if _, err := f.env.Super.Exec(context.Background(),
						`UPDATE device_enrollments SET cert_delivered_at = NULL WHERE device_id = $1`, tdDevID); err != nil {
						t.Fatal(err)
					}
				}
				if err := f.env.Services.Devices.Reassign(context.Background(), f.device, tdHome); err != nil {
					t.Fatalf("reassign: %v", err)
				}
				p.run(f)
				if n := count(t, f, `SELECT count(*) FROM device_enrollments WHERE device_id = $1`, tdDevID); n != 0 {
					t.Fatalf("enrollment rows left = %d, want 0", n)
				}
			})
		}
	}
}

const (
	td2DevID  = "thesada-0a0b0c0d0e10"
	td2Pub    = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	td2Serial = "cd34"
)

// seedSecondDevice adds a second paired, sealed device to tdGone.
// in: t, fixture. out: none.
func seedSecondDevice(t *testing.T, f tdFixture) {
	t.Helper()
	ctx := context.Background()
	pk, err := f.env.Services.Devices.Upsert(tdGone, td2DevID, "", "", "", "thesada/"+tdGone+"/"+td2DevID)
	if err != nil {
		t.Fatalf("seed second device: %v", err)
	}
	now := time.Now()
	if err := f.env.Services.Certificates.IssueWithIdentity(ctx, tdGone, pk, td2Serial, "cn2",
		now.Add(-time.Hour), now.Add(time.Hour), "pem", td2Pub); err != nil {
		t.Fatalf("issue second cert: %v", err)
	}
	if _, err := f.env.Super.Exec(ctx,
		`INSERT INTO device_enrollments (device_id, pubkey_hex, claim_token_hash, verified_at, claimed_by_tenant, claimed_at, cert_delivered_at)
		 VALUES ($1, $2, 'w', now(), $3, now(), now())`, td2DevID, td2Pub, tdGone); err != nil {
		t.Fatalf("seed second enrollment: %v", err)
	}
}

// goneUUID is tdGone's tenant uuid, the identity a delete job carries.
func goneUUID(t *testing.T, f tdFixture) uuid.UUID {
	t.Helper()
	tn, err := f.env.Services.Tenants.Get(tdGone)
	if err != nil {
		t.Fatalf("get %s: %v", tdGone, err)
	}
	return tn.UUID
}

// shutdownRun is one delete job body, run on ctx with a progress hook.
type shutdownRun struct {
	name string
	run  func(t *testing.T, f tdFixture, ctx context.Context, devices []service.Device, progress func(int))
}

// shutdownRuns drives the tenant and bulk job bodies and checks each one's
// own outcome: the tenant is kept, or the bulk flash is the mixed one.
var shutdownRuns = []shutdownRun{
	{"tenant", func(t *testing.T, f tdFixture, ctx context.Context, devices []service.Device, progress func(int)) {
		loc := f.s.deleteTenant(ctx, &service.User{Email: "op@example.com"}, goneUUID(t, f), tdGone, tdHome, devices, true, progress)
		if !strings.Contains(loc, flashTenantKept.query()) {
			t.Errorf("stopped tenant job sent the operator to %q, want kept", loc)
		}
	}},
	{"bulk", func(t *testing.T, f tdFixture, ctx context.Context, devices []service.Device, progress func(int)) {
		loc := f.s.bulkDeleteRun(ctx, &service.User{Email: "op@example.com"},
			[]*service.Device{&devices[0], &devices[1]}, 1, 0, 2, true, progress)
		if !strings.HasPrefix(loc, flashAdminBulkDeletedMix.on("/admin/devices")) {
			t.Errorf("stopped bulk job sent the operator to %q, want the mixed flash", loc)
		}
	}},
}

// assertUntouched checks a device the job never reached: row, live cert and
// sealed enrollment all still there.
func assertUntouched(t *testing.T, f tdFixture, d service.Device) {
	t.Helper()
	if n := count(t, f, `SELECT count(*) FROM device_certificates WHERE device_pk = $1 AND NOT revoked`, d.ID); n != 1 {
		t.Errorf("%s live certs = %d, want 1", d.DeviceID, n)
	}
	if n := count(t, f, `SELECT count(*) FROM device_enrollments
		WHERE device_id = $1 AND cert_delivered_at IS NOT NULL`, d.DeviceID); n != 1 {
		t.Errorf("%s sealed enrollment rows = %d, want 1", d.DeviceID, n)
	}
}

// stoppedAudit counts stopped-for-shutdown rows that report notStarted
// devices and name revokedKept (empty: none named).
func stoppedAudit(t *testing.T, f tdFixture, notStarted int, revokedKept string) int {
	t.Helper()
	if revokedKept == "" {
		return count(t, f, `SELECT count(*) FROM admin_audit
			WHERE detail->>'stopped_for_shutdown' = 'true' AND (detail->>'not_started')::int = $1
			  AND jsonb_typeof(detail->'revoked_not_deleted') = 'null'`, notStarted)
	}
	return count(t, f, `SELECT count(*) FROM admin_audit
		WHERE detail->>'stopped_for_shutdown' = 'true' AND (detail->>'not_started')::int = $1
		  AND detail->'revoked_not_deleted' = jsonb_build_array($2::text)`, notStarted, revokedKept)
}

// tenantDevices lists tdGone's two devices in job order.
func tenantDevices(t *testing.T, f tdFixture) []service.Device {
	t.Helper()
	devices, err := f.env.Services.Devices.ListByTenant(tdGone)
	if err != nil || len(devices) != 2 {
		t.Fatalf("list devices = %d, %v, want 2", len(devices), err)
	}
	return devices
}

// A drain about to give up stops the device in progress before its DB delete:
// the row stays, revoked, for a retry, and the stop audit row names it.
func TestAdminDeleteJobs_ShutdownNearTheDeadlineStopsBeforeTheDBDelete(t *testing.T) {
	for _, r := range shutdownRuns {
		t.Run(r.name, func(t *testing.T) {
			f := seedTenantDelete(t)
			seedSecondDevice(t, f)
			devices := tenantDevices(t, f)
			drainCtx, drainCancel := context.WithTimeout(context.Background(), time.Second)
			defer drainCancel()
			if err := f.s.DrainJobs(drainCtx); err != nil {
				t.Fatalf("drain with no jobs: %v", err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.run(t, f, ctx, devices, func(done int) {
				if done == 0 {
					cancel()
				}
			})
			if n := count(t, f, `SELECT count(*) FROM devices WHERE tenant_id = $1`, tdGone); n != 2 {
				t.Fatalf("devices left = %d, want 2", n)
			}
			if n := count(t, f, `SELECT count(*) FROM device_certificates WHERE device_pk = $1 AND NOT revoked`, devices[0].ID); n != 0 {
				t.Errorf("stopped device still has %d live certs, want it revoked", n)
			}
			assertUntouched(t, f, devices[1])
			if n := stoppedAudit(t, f, 1, devices[0].DeviceID); n != 1 {
				t.Errorf("stop audit rows naming %s = %d, want 1", devices[0].DeviceID, n)
			}
		})
	}
}

// Shutdown with time left lets the device in progress finish: delete,
// enrollment reset, tombstone and audit row. The next device is never started.
func TestAdminDeleteJobs_ShutdownFinishesTheDeviceInProgress(t *testing.T) {
	for _, r := range shutdownRuns {
		t.Run(r.name, func(t *testing.T) {
			f := seedTenantDelete(t)
			seedSecondDevice(t, f)
			devices := tenantDevices(t, f)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			r.run(t, f, ctx, devices, func(done int) {
				if done == 0 {
					cancel()
				}
			})
			if n := count(t, f, `SELECT count(*) FROM devices WHERE id = $1`, devices[0].ID); n != 0 {
				t.Fatal("device in progress survived")
			}
			if n := count(t, f, `SELECT count(*) FROM device_enrollments WHERE device_id = $1`, devices[0].DeviceID); n != 0 {
				t.Errorf("finished device enrollment rows = %d, want 0", n)
			}
			if n := count(t, f, `SELECT count(*) FROM deleted_device_tombstones WHERE device_id = $1`, devices[0].DeviceID); n != 1 {
				t.Errorf("finished device tombstones = %d, want 1", n)
			}
			if n := count(t, f, `SELECT count(*) FROM admin_audit WHERE action = 'device.delete' AND target_id = $1`,
				devices[0].ID.String()); n != 1 {
				t.Errorf("finished device.delete audit rows = %d, want 1", n)
			}
			assertUntouched(t, f, devices[1])
			if n := stoppedAudit(t, f, 1, ""); n != 1 {
				t.Errorf("stop audit rows with one not started = %d, want 1", n)
			}
		})
	}
}

// A device reassigned after the job read it is skipped: no cert clear, no
// revoke, no delete in the tenant it moved to.
func TestAdminDeleteJobs_SkipADeviceThatMovedTenant(t *testing.T) {
	f := seedTenantDelete(t)
	snapshot := *deviceByID(t, f.env, f.device)
	if _, err := f.env.Super.Exec(context.Background(),
		`UPDATE devices SET tenant_id = $1 WHERE id = $2`, tdHome, snapshot.ID); err != nil {
		t.Fatal(err)
	}
	verdict, _ := f.s.cascadeDeleteOne(context.Background(), "bulk delete", "op@example.com",
		&snapshot, recoveryVerdict{usable: true}, true)
	if verdict != cascadeMoved {
		t.Fatalf("verdict = %v, want cascadeMoved", verdict)
	}
	if n := count(t, f, `SELECT count(*) FROM devices WHERE id = $1 AND tenant_id = $2`, snapshot.ID, tdHome); n != 1 {
		t.Fatal("the moved device was deleted")
	}
	if n := count(t, f, `SELECT count(*) FROM device_certificates WHERE device_pk = $1 AND NOT revoked`, snapshot.ID); n != 1 {
		t.Fatalf("the moved device's live certs = %d, want 1", n)
	}
	if n := count(t, f, `SELECT count(*) FROM device_enrollments WHERE device_id = $1`, snapshot.DeviceID); n != 2 {
		t.Fatalf("the moved device's enrollment rows = %d, want 2", n)
	}
}

// A device paired after the job read it meets the recovery gate it now needs.
func TestAdminDeleteJobs_GateSeesAPairingMadeDuringTheJob(t *testing.T) {
	f := seedTenantDelete(t)
	ctx := context.Background()
	if _, err := f.env.Super.Exec(ctx, `UPDATE devices SET paired_at = NULL WHERE id = $1`, f.device); err != nil {
		t.Fatal(err)
	}
	snapshot := *deviceByID(t, f.env, f.device)
	if _, err := f.env.Super.Exec(ctx, `UPDATE devices SET paired_at = now() WHERE id = $1`, f.device); err != nil {
		t.Fatal(err)
	}
	verdict, _ := f.s.cascadeDeleteOne(ctx, "tenant delete", "op@example.com",
		&snapshot, recoveryVerdict{reason: "fallback disabled"}, false)
	if verdict != cascadeRefused {
		t.Fatalf("verdict = %v, want cascadeRefused for a device paired mid-job", verdict)
	}
	if n := count(t, f, `SELECT count(*) FROM device_certificates WHERE device_pk = $1 AND NOT revoked`, f.device); n != 1 {
		t.Fatalf("live certs = %d, want the fresh pairing untouched", n)
	}
}

// Revoke and DeleteByID under a tenant that no longer owns the row fail
// instead of reporting a delete that matched nothing.
func TestDeviceWrites_ZeroRowsUnderAnotherTenantFail(t *testing.T) {
	f := seedTenantDelete(t)
	ctx := context.Background()
	if err := f.env.Services.Certificates.Revoke(ctx, tdHome, f.device); !errors.Is(err, service.ErrDeviceNotInTenant) {
		t.Fatalf("Revoke under another tenant = %v, want ErrDeviceNotInTenant", err)
	}
	if n := count(t, f, `SELECT count(*) FROM device_certificates WHERE device_pk = $1 AND NOT revoked`, f.device); n != 1 {
		t.Fatalf("live certs after a refused revoke = %d, want 1", n)
	}
	if err := f.env.Services.Devices.DeleteByID(ctx, tdHome, f.device); !errors.Is(err, service.ErrDeviceNotInTenant) {
		t.Fatalf("DeleteByID under another tenant = %v, want ErrDeviceNotInTenant", err)
	}
}

// A sealed enrollment is reported even when the tenant is kept: on the
// device.delete row and in the flash.
func TestAdminTenantDelete_KeptTenantStillReportsASealedDevice(t *testing.T) {
	f := seedTenantDelete(t)
	seedSecondDevice(t, f)
	ctx := context.Background()
	devices := tenantDevices(t, f)
	refused, deleted := devices[0], devices[1]
	if _, err := f.env.Super.Exec(ctx, `UPDATE devices SET paired_at = now() WHERE id = $1`, refused.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.env.Super.Exec(ctx, `UPDATE devices SET paired_at = NULL WHERE id = $1`, deleted.ID); err != nil {
		t.Fatal(err)
	}
	// Held until the job ends, so the deleted device's enrollment reset times out.
	tx, err := f.env.Super.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `LOCK TABLE device_enrollments IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	loc := f.s.deleteTenant(ctx, &service.User{Email: "op@example.com"}, goneUUID(t, f), tdGone, tdHome,
		tenantDevices(t, f), false, func(int) {})
	if err := tx.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(loc, flashTenantKept.query()) || !strings.Contains(loc, flashTenantIncomplete.query()) {
		t.Fatalf("job sent the operator to %q, want kept and incomplete", loc)
	}
	if n := count(t, f, `SELECT count(*) FROM admin_audit WHERE action = 'device.delete' AND target_id = $1
		AND detail->>'enroll_reset_failed' = 'true'`, deleted.ID.String()); n != 1 {
		t.Fatalf("device.delete rows flagging the sealed enrollment = %d, want 1", n)
	}
}
