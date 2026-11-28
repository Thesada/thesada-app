//go:build integration

// Device reads of config.json fill gaps in the encrypted secret store and keep the
// open WiFi markers, ordered by the database clock against config changes (C1, #99).
//
//	go test -tags integration -run TestUpsertFromDevice ./pkg/service/...
package service_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestUpsertFromDevice(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()

	cfg := *env.Cfg
	cfg.DeviceConfigKEK = testKEK
	svcs, err := service.New(&cfg, env.Pools)
	if err != nil {
		t.Fatalf("service.New with KEK: %v", err)
	}
	df, sec := svcs.DeviceFiles, svcs.Secrets

	const tA = "dfs-a"
	env.SeedTenant(t, tA)

	reveal := func(t *testing.T, pk uuid.UUID, field string) (string, bool) {
		t.Helper()
		v, found, err := sec.Reveal(ctx, tA, pk, field)
		if err != nil {
			t.Fatalf("Reveal %s: %v", field, err)
		}
		return v, found
	}
	start := func(t *testing.T) time.Time {
		t.Helper()
		s, err := df.ReadStart(ctx, tA)
		if err != nil {
			t.Fatalf("ReadStart: %v", err)
		}
		return s
	}
	read := func(t *testing.T, pk uuid.UUID, content, sha string, at time.Time) {
		t.Helper()
		if _, err := df.UpsertFromDevice(ctx, tA, pk, "config.json", content, sha, "drift", nil, at); err != nil {
			t.Fatalf("UpsertFromDevice: %v", err)
		}
	}
	open := func(t *testing.T, d *service.DeviceFilesService, pk uuid.UUID, ssid string) bool {
		t.Helper()
		ok, err := d.OpenNetworkCurrent(ctx, tA, pk, ssid)
		if err != nil {
			t.Fatalf("OpenNetworkCurrent %s: %v", ssid, err)
		}
		return ok
	}
	changed := func(t *testing.T, pk uuid.UUID) {
		t.Helper()
		if err := df.MarkConfigChanged(ctx, tA, pk); err != nil {
			t.Fatalf("MarkConfigChanged: %v", err)
		}
	}
	markers := func(t *testing.T, pk uuid.UUID) int {
		t.Helper()
		var n int
		if err := env.Super.QueryRow(ctx, `SELECT count(*) FROM device_open_networks WHERE device_pk = $1`, pk).Scan(&n); err != nil {
			t.Fatalf("count markers: %v", err)
		}
		return n
	}
	const openCafe = `{"wifi":{"networks":[{"ssid":"cafe","password":""}]}}`

	t.Run("a_read_fills_gaps_and_records_open_networks", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-1", "", "", "", "")
		content := `{"mqtt":{"password":"mq-secret"},"wifi":{"networks":[` +
			`{"ssid":"home","password":"pw-home"},{"ssid":"cafe","password":""}]}}`
		read(t, pk, content, "sha-1", start(t))
		latest, err := df.Latest(ctx, tA, pk, "config.json")
		if err != nil || latest == nil {
			t.Fatalf("Latest = %v, %v", latest, err)
		}
		for _, plain := range []string{"mq-secret", "pw-home"} {
			if strings.Contains(latest.Content, plain) {
				t.Errorf("snapshot still holds %q", plain)
			}
		}
		if v, _ := reveal(t, pk, "mqtt.password"); v != "mq-secret" {
			t.Errorf("mqtt.password = %q, want mq-secret", v)
		}
		if v, _ := reveal(t, pk, "wifi.password:home"); v != "pw-home" {
			t.Errorf("wifi home = %q, want pw-home", v)
		}
		if _, found := reveal(t, pk, "wifi.password:cafe"); found {
			t.Error("an open network landed in the secret store")
		}
		if !open(t, df, pk, "cafe") || open(t, df, pk, "home") {
			t.Error("want cafe open and home not")
		}
	})

	// The firmware resolves NVS before config.json: "" or an old plaintext in
	// config.json says nothing about the stored secret (C1).
	t.Run("an_empty_or_stale_password_never_overwrites_a_stored_one", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-2", "", "", "", "")
		if err := sec.SetSecret(ctx, tA, pk, "wifi.password:home", "pw"); err != nil {
			t.Fatalf("seed: %v", err)
		}
		read(t, pk, `{"wifi":{"networks":[{"ssid":"home","password":""}]}}`, "sha-e", start(t))
		if v, _ := reveal(t, pk, "wifi.password:home"); v != "pw" {
			t.Errorf("home after an empty read = %q, want pw", v)
		}
		read(t, pk, `{"wifi":{"networks":[{"ssid":"home","password":"old"}]}}`, "sha-o", start(t))
		if v, _ := reveal(t, pk, "wifi.password:home"); v != "pw" {
			t.Errorf("home after a stale plaintext read = %q, want pw", v)
		}
	})

	// A marker is a fact about the file. What NVS holds is the write guard's secret.info question.
	t.Run("an_empty_password_is_marked_open_whatever_the_store_holds", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-14", "", "", "", "")
		if err := sec.SetSecret(ctx, tA, pk, "wifi.password:cafe", "pw"); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := sec.SetTenantSecret(ctx, tA, "wifi.password:office", "tenant-pw"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		read(t, pk, `{"wifi":{"networks":[{"ssid":"cafe","password":""},{"ssid":"office","password":""},`+
			`{"ssid":"park","password":""}]}}`, "sha-s", start(t))
		for _, ssid := range []string{"cafe", "office", "park"} {
			if !open(t, df, pk, ssid) {
				t.Errorf("%s reads empty in the file, want it marked open", ssid)
			}
		}
		if v, _ := reveal(t, pk, "wifi.password:cafe"); v != "pw" {
			t.Errorf("cafe = %q, want the stored password kept", v)
		}
	})

	// Storing a password changes NVS only once it is provisioned, never the file the marker describes.
	t.Run("set_secret_does_not_change_the_file_fact", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-18", "", "", "", "")
		read(t, pk, openCafe, "sha-f", start(t))
		if err := sec.SetSecret(ctx, tA, pk, "wifi.password:cafe", "later"); err != nil {
			t.Fatalf("SetSecret: %v", err)
		}
		if !open(t, df, pk, "cafe") {
			t.Error("SetSecret changed the file fact")
		}
	})

	// Device secrets are AAD-bound to the tenant, which a same-tenant reassign keeps.
	t.Run("a_reassign_to_the_same_tenant_keeps_device_secrets", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-15", "", "", "", "")
		if err := sec.SetSecret(ctx, tA, pk, "mqtt.password", "keep-me"); err != nil {
			t.Fatalf("seed: %v", err)
		}
		if err := svcs.Devices.Reassign(ctx, pk, tA); err != nil {
			t.Fatalf("Reassign: %v", err)
		}
		if v, found := reveal(t, pk, "mqtt.password"); !found || v != "keep-me" {
			t.Errorf("mqtt.password after a same-tenant reassign = %q (found %v), want keep-me", v, found)
		}
	})

	t.Run("tenant_default_stays_inherited", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-3", "", "", "", "")
		if err := sec.SetTenantSecret(ctx, tA, "wifi.password:shop", "tenant-pw"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		for i, pw := range []string{"tenant-pw", "local-pw", ""} {
			read(t, pk, `{"wifi":{"networks":[{"ssid":"shop","password":"`+pw+`"}]}}`, "sha-t"+string(rune('0'+i)), start(t))
			origins, err := sec.OriginStatus(ctx, tA, pk)
			if err != nil {
				t.Fatalf("OriginStatus: %v", err)
			}
			if got := origins["wifi.password:shop"]; got != service.OriginTenant {
				t.Errorf("origin after a read of %q = %q, want tenant", pw, got)
			}
		}
	})

	t.Run("a_password_in_a_current_read_clears_the_marker", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-4", "", "", "", "")
		read(t, pk, openCafe, "sha-a", start(t))
		if !open(t, df, pk, "cafe") {
			t.Fatal("precondition: cafe open")
		}
		read(t, pk, strings.Replace(openCafe, `"password":""`, `"password":"now-locked"`, 1), "sha-b", start(t))
		if open(t, df, pk, "cafe") || markers(t, pk) != 0 {
			t.Error("the cafe marker survived a read with its password")
		}
		if v, _ := reveal(t, pk, "wifi.password:cafe"); v != "now-locked" {
			t.Errorf("cafe = %q, want the gap filled with now-locked", v)
		}
	})

	t.Run("a_marker_older_than_a_config_change_does_not_count", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-5", "", "", "", "")
		read(t, pk, openCafe, "sha-a", start(t))
		changed(t, pk)
		if open(t, df, pk, "cafe") {
			t.Error("a marker seen before the config change still counts")
		}
		read(t, pk, openCafe, "sha-a", start(t))
		if !open(t, df, pk, "cafe") {
			t.Error("a read after the change did not restore the marker")
		}
	})

	t.Run("a_new_service_instance_still_refuses_a_stale_marker", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-6", "", "", "", "")
		read(t, pk, openCafe, "sha-a", start(t))
		before := start(t)
		changed(t, pk)
		restarted, err := service.New(&cfg, env.Pools)
		if err != nil {
			t.Fatalf("service.New: %v", err)
		}
		if open(t, restarted.DeviceFiles, pk, "cafe") {
			t.Error("a restart made a stale marker count again")
		}
		if _, err := restarted.DeviceFiles.UpsertFromDevice(ctx, tA, pk, "config.json", openCafe, "sha-r", "drift", nil, before); err != nil {
			t.Fatalf("UpsertFromDevice: %v", err)
		}
		if open(t, restarted.DeviceFiles, pk, "cafe") {
			t.Error("a read from before the change restored the marker after a restart")
		}
	})

	// A read that started before the last config change writes nothing (M5).
	t.Run("a_stale_read_writes_nothing", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-7", "", "", "", "")
		read(t, pk, `{"device":{"name":"new"}}`, "sha-new", start(t))
		readStarted := start(t)
		changed(t, pk)
		stale := `{"device":{"name":"old"},"mqtt":{"password":"mq"},"wifi":{"networks":[{"ssid":"cafe","password":""}]}}`
		if stored, err := df.UpsertFromDevice(ctx, tA, pk, "config.json", stale, "sha-old", "drift", nil, readStarted); err != nil || stored {
			t.Fatalf("stale UpsertFromDevice = %v, %v, want dropped with a nil error", stored, err)
		}
		latest, err := df.Latest(ctx, tA, pk, "config.json")
		if err != nil || latest == nil || latest.SHA256 != "sha-new" {
			t.Fatalf("snapshot after a stale read = %+v, %v, want sha-new", latest, err)
		}
		if _, found := reveal(t, pk, "mqtt.password"); found {
			t.Error("a stale read filled a gap")
		}
		if markers(t, pk) != 0 {
			t.Error("a stale read recorded a marker")
		}
		if stored, err := df.UpsertFromDevice(ctx, tA, pk, "config.json", `{"device":{"name":"new"}}`, "sha-new2", "drift", nil, start(t)); err != nil || !stored {
			t.Fatalf("current UpsertFromDevice = %v, %v, want stored", stored, err)
		}
	})

	// Two reads answer out of order: the older one is dropped (#98 item 1).
	t.Run("an_older_read_after_a_newer_one_is_dropped", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-8", "", "", "", "")
		first, second := start(t), start(t)
		read(t, pk, `{"wifi":{"networks":[{"ssid":"cafe","password":"locked"}]}}`, "sha-2", second)
		read(t, pk, openCafe, "sha-1", first)
		if open(t, df, pk, "cafe") {
			t.Error("the older read marked cafe open")
		}
		if latest, _ := df.Latest(ctx, tA, pk, "config.json"); latest == nil || latest.SHA256 != "sha-2" {
			t.Errorf("snapshot = %+v, want the newer read", latest)
		}
	})

	// A failure part way leaves nothing behind: no gap fill, no marker, no snapshot (M7).
	t.Run("a_failed_refresh_rolls_back_whole", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-9", "", "", "", "")
		// Postgres text refuses NUL, so the marker step fails after mqtt.password was filled.
		bad := `{"mqtt":{"password":"mq"},"wifi":{"networks":[{"ssid":"bad\u0000","password":""}]}}`
		if _, err := df.UpsertFromDevice(ctx, tA, pk, "config.json", bad, "sha-bad", "drift", nil, start(t)); err == nil {
			t.Fatal("UpsertFromDevice with a NUL SSID succeeded, the failure path never ran")
		}
		if _, found := reveal(t, pk, "mqtt.password"); found {
			t.Error("mqtt.password stayed after the refresh failed")
		}
		if latest, _ := df.Latest(ctx, tA, pk, "config.json"); latest != nil {
			t.Errorf("snapshot = %+v, want none", latest)
		}
	})

	// Rows keyed on the device but tagged with the old tenant must not block reads after a reassign.
	t.Run("a_read_after_a_reassign_stores_under_the_new_tenant", func(t *testing.T) {
		const tB = "dfs-b"
		env.SeedTenant(t, tB)
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-13", "", "", "", "")
		content := `{"wifi":{"networks":[{"ssid":"home","password":"pw-a"},{"ssid":"cafe","password":""}]}}`
		read(t, pk, content, "sha-a", start(t))
		if err := svcs.Devices.Reassign(ctx, pk, tB); err != nil {
			t.Fatalf("Reassign: %v", err)
		}
		at, err := df.ReadStart(ctx, tB)
		if err != nil {
			t.Fatalf("ReadStart: %v", err)
		}
		moved := strings.Replace(content, "pw-a", "pw-b", 1)
		if _, err := df.UpsertFromDevice(ctx, tB, pk, "config.json", moved, "sha-b", "drift", nil, at); err != nil {
			t.Fatalf("read under the new tenant: %v", err)
		}
		var n int
		if err := env.Super.QueryRow(ctx,
			`SELECT count(*) FROM device_open_networks WHERE device_pk = $1 AND tenant_id = $2 AND ssid = 'cafe'`, pk, tB).Scan(&n); err != nil || n != 1 {
			t.Errorf("cafe markers under the new tenant = %d (%v), want 1", n, err)
		}
		if v, _, err := sec.Reveal(ctx, tB, pk, "wifi.password:home"); err != nil || v != "pw-b" {
			t.Errorf("home under the new tenant = %q (%v), want the gap filled with pw-b", v, err)
		}
		if latest, _ := df.Latest(ctx, tB, pk, "config.json"); latest == nil || latest.SHA256 != "sha-b" {
			t.Errorf("snapshot = %+v, want the read under the new tenant", latest)
		}
	})

	// A bare legacy row moves to the primary SSID on a current read, and a stale plaintext never replaces it.
	t.Run("a_legacy_password_is_rekeyed_to_the_primary_ssid", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-16", "", "", "", "")
		if err := sec.PlantLegacyWifi(ctx, tA, pk, "legacy-pw"); err != nil {
			t.Fatalf("seed: %v", err)
		}
		read(t, pk, `{"wifi":{"networks":[{"ssid":"home","password":""},{"ssid":"park","password":""}]}}`, "sha-l", start(t))
		if !open(t, df, pk, "home") || !open(t, df, pk, "park") {
			t.Error("both networks read empty in the file, want both marked open")
		}
		read(t, pk, `{"wifi":{"networks":[{"ssid":"home","password":"stale"}]}}`, "sha-l2", start(t))
		if v, _ := reveal(t, pk, "wifi.password:home"); v != "legacy-pw" {
			t.Errorf("wifi.password:home = %q, want the re-keyed legacy value", v)
		}
	})

	// SetSecret takes the device row lock before its insert, in the read path's order.
	t.Run("set_secret_beside_a_read_does_not_deadlock", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-17", "", "", "", "")
		if err := sec.EnsureTenantDEK(ctx, tA); err != nil {
			t.Fatalf("EnsureTenantDEK: %v", err)
		}
		// The read path: device row locked, then the insert of a field the store lacks.
		reader, err := env.Super.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = reader.Rollback(ctx) }()
		if _, err := reader.Exec(ctx, `SELECT 1 FROM devices WHERE id = $1 FOR UPDATE`, pk); err != nil {
			t.Fatal(err)
		}
		setErr := make(chan error, 1)
		go func() { setErr <- sec.SetSecret(ctx, tA, pk, "web.password", "from-ui") }()
		waitForLockWait(t, env)
		_, insErr := reader.Exec(ctx, `
			INSERT INTO device_config_secrets (tenant_id, device_pk, field, ciphertext)
			VALUES ($1, $2, 'web.password', $3)
			ON CONFLICT (device_pk, field) WHERE device_pk IS NOT NULL DO NOTHING`,
			tA, pk, make([]byte, 40))
		if insErr == nil {
			insErr = reader.Commit(ctx)
		}
		if insErr != nil {
			t.Errorf("read path insert: %v", insErr)
		}
		if err := <-setErr; err != nil {
			t.Errorf("SetSecret beside a read: %v", err)
		}
	})

	t.Run("an_empty_value_is_not_a_secret", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-10", "", "", "", "")
		if err := sec.SetSecret(ctx, tA, pk, "mqtt.password", ""); !errors.Is(err, service.ErrEmptySecret) {
			t.Errorf("SetSecret empty = %v, want ErrEmptySecret", err)
		}
		if err := sec.SetTenantSecret(ctx, tA, "mqtt.password", ""); !errors.Is(err, service.ErrEmptySecret) {
			t.Errorf("SetTenantSecret empty = %v, want ErrEmptySecret", err)
		}
	})

	// Masked firmware reads (set) or (empty) for a secret: neither is a value.
	t.Run("a_masked_read_stores_no_secret", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-20", "", "", "", "")
		content := `{"mqtt":{"password":"(set)"},"web":{"password":"(empty)"},"wifi":{"networks":[` +
			`{"ssid":"home","password":"(set)"},{"ssid":"cafe","password":"(empty)"}]}}`
		read(t, pk, content, "sha-masked", start(t))
		for _, f := range []string{"mqtt.password", "web.password", "wifi.password:home", "wifi.password:cafe"} {
			if v, found := reveal(t, pk, f); found {
				t.Errorf("%s stored as %q, want nothing", f, v)
			}
		}
		if !open(t, df, pk, "cafe") || open(t, df, pk, "home") {
			t.Error("want cafe open and home not")
		}
		latest, err := df.Latest(ctx, tA, pk, "config.json")
		if err != nil || latest == nil || latest.SHA256 != "sha-masked" {
			t.Fatalf("Latest = %+v, %v", latest, err)
		}
		if service.HasMaskMarker(latest.Content) {
			t.Errorf("snapshot keeps a marker: %s", latest.Content)
		}
		// The same device on old firmware still fills the gap from its clear value.
		read(t, pk, `{"mqtt":{"password":"mq-clear"}}`, "sha-clear", start(t))
		if v, _ := reveal(t, pk, "mqtt.password"); v != "mq-clear" {
			t.Errorf("mqtt.password after a clear read = %q, want mq-clear", v)
		}
	})

	t.Run("a_marker_is_never_a_secret_value", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-21", "", "", "", "")
		for _, m := range []string{"(set)", "(empty)"} {
			if err := sec.SetSecret(ctx, tA, pk, "mqtt.password", m); !errors.Is(err, service.ErrMarkerSecret) {
				t.Errorf("SetSecret %s = %v, want ErrMarkerSecret", m, err)
			}
			if err := sec.SetTenantSecret(ctx, tA, "mqtt.password", m); !errors.Is(err, service.ErrMarkerSecret) {
				t.Errorf("SetTenantSecret %s = %v, want ErrMarkerSecret", m, err)
			}
		}
		if err := sec.SetSecret(ctx, tA, pk, "mqtt.password", "(set)!"); err != nil {
			t.Errorf("a longer value holding a marker: %v", err)
		}
	})

	t.Run("operator_content_never_reaches_the_store", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-11", "", "", "", "")
		content := `{"wifi":{"networks":[{"ssid":"lab","password":""}]},"mqtt":{"password":"typed"}}`
		if err := df.Upsert(ctx, tA, pk, "config.json", content, "sha-op", "read", nil); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if open(t, df, pk, "lab") {
			t.Error("operator snapshot marked a network open")
		}
		if _, found := reveal(t, pk, "mqtt.password"); found {
			t.Error("operator snapshot wrote a secret to the store")
		}
	})

	t.Run("feature_off_still_blanks_and_orders", func(t *testing.T) {
		offCfg := *env.Cfg
		offCfg.DeviceConfigKEK = ""
		off, err := service.New(&offCfg, env.Pools)
		if err != nil {
			t.Fatalf("service.New without KEK: %v", err)
		}
		if off.Secrets.Enabled() {
			t.Fatal("services without a KEK report the store enabled")
		}
		pk := mustUpsert(t, off.Devices, tA, "dfs-dev-12", "", "", "", "")
		content := `{"wifi":{"networks":[{"ssid":"home","password":"pw"},{"ssid":"cafe","password":""}]}}`
		at, err := off.DeviceFiles.ReadStart(ctx, tA)
		if err != nil {
			t.Fatalf("ReadStart: %v", err)
		}
		if _, err := off.DeviceFiles.UpsertFromDevice(ctx, tA, pk, "config.json", content, "sha-off", "pull", nil, at); err != nil {
			t.Fatalf("UpsertFromDevice feature off: %v", err)
		}
		latest, err := off.DeviceFiles.Latest(ctx, tA, pk, "config.json")
		if err != nil || latest == nil || strings.Contains(latest.Content, `"pw"`) {
			t.Fatalf("feature-off snapshot = %v, %v, want blanked", latest, err)
		}
		if _, found := reveal(t, pk, "wifi.password:home"); found {
			t.Error("feature off wrote to the store")
		}
		if markers(t, pk) != 1 {
			t.Error("feature off did not record the open cafe, a file fact the guard needs")
		}
		if err := off.DeviceFiles.MarkConfigChanged(ctx, tA, pk); err != nil {
			t.Fatalf("MarkConfigChanged: %v", err)
		}
		if _, err := off.DeviceFiles.UpsertFromDevice(ctx, tA, pk, "config.json", `{}`, "sha-late", "pull", nil, at); err != nil {
			t.Fatalf("stale UpsertFromDevice: %v", err)
		}
		if latest, _ := off.DeviceFiles.Latest(ctx, tA, pk, "config.json"); latest == nil || latest.SHA256 != "sha-off" {
			t.Errorf("feature off stored a stale read: %+v", latest)
		}
	})
}

// waitForLockWait returns once another backend waits on a lock, or fails after 10 s.
func waitForLockWait(t *testing.T, env *servicetest.Env) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		var n int
		if err := env.Super.QueryRow(context.Background(),
			`SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND pid <> pg_backend_pid()`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			return
		}
	}
	t.Fatal("SetSecret never waited on the locked device row")
}
