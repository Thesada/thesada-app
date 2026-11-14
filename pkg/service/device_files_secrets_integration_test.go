//go:build integration

// Device reads of config.json feed the encrypted secret store before the
// snapshot is blanked, so the store knows every password and every open
// network the device reported (#88).
//
//	go test -tags integration -run TestUpsertFromDevice ./pkg/service/...
package service_test

import (
	"context"
	"strings"
	"testing"

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

	t.Run("extracts_passwords_and_open_networks", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-1", "", "", "", "")
		content := `{"mqtt":{"password":"mq-secret"},"wifi":{"networks":[` +
			`{"ssid":"home","password":"pw-home"},{"ssid":"cafe","password":""}]}}`
		if err := df.UpsertFromDevice(ctx, tA, pk, "config.json", content, "sha-1", "pull", nil); err != nil {
			t.Fatalf("UpsertFromDevice: %v", err)
		}
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
		if v, found := reveal(t, pk, "wifi.password:cafe"); !found || v != "" {
			t.Errorf("wifi cafe = %q found=%v, want a stored open network", v, found)
		}

		// The network gets a password on the device: the next read replaces the open marker.
		content = strings.Replace(content, `"ssid":"cafe","password":""`, `"ssid":"cafe","password":"now-locked"`, 1)
		if err := df.UpsertFromDevice(ctx, tA, pk, "config.json", content, "sha-2", "pull", nil); err != nil {
			t.Fatalf("UpsertFromDevice 2: %v", err)
		}
		if v, _ := reveal(t, pk, "wifi.password:cafe"); v != "now-locked" {
			t.Errorf("wifi cafe after second read = %q, want now-locked", v)
		}
	})

	// A device on the tenant default reports that value back. It must keep
	// inheriting, or the next default rotation would skip it as overridden.
	t.Run("tenant_default_stays_inherited", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-4", "", "", "", "")
		if err := sec.SetTenantSecret(ctx, tA, "wifi.password:shop", "tenant-pw"); err != nil {
			t.Fatalf("SetTenantSecret: %v", err)
		}
		content := `{"wifi":{"networks":[{"ssid":"shop","password":"tenant-pw"}]}}`
		if err := df.UpsertFromDevice(ctx, tA, pk, "config.json", content, "sha-t1", "pull", nil); err != nil {
			t.Fatalf("UpsertFromDevice: %v", err)
		}
		origins, err := sec.OriginStatus(ctx, tA, pk)
		if err != nil {
			t.Fatalf("OriginStatus: %v", err)
		}
		if got := origins["wifi.password:shop"]; got != service.OriginTenant {
			t.Errorf("origin after matching read = %q, want tenant", got)
		}

		// The device moved off the default: now it is a real override.
		content = strings.Replace(content, `tenant-pw`, `local-pw`, 1)
		if err := df.UpsertFromDevice(ctx, tA, pk, "config.json", content, "sha-t2", "pull", nil); err != nil {
			t.Fatalf("UpsertFromDevice 2: %v", err)
		}
		if v, _ := reveal(t, pk, "wifi.password:shop"); v != "local-pw" {
			t.Errorf("override = %q, want local-pw", v)
		}
	})

	t.Run("operator_content_never_reaches_the_store", func(t *testing.T) {
		pk := mustUpsert(t, svcs.Devices, tA, "dfs-dev-2", "", "", "", "")
		content := `{"wifi":{"networks":[{"ssid":"lab","password":""}]},"mqtt":{"password":"typed"}}`
		if err := df.Upsert(ctx, tA, pk, "config.json", content, "sha-op", "read", nil); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if _, found := reveal(t, pk, "wifi.password:lab"); found {
			t.Error("operator snapshot marked a network open")
		}
		if _, found := reveal(t, pk, "mqtt.password"); found {
			t.Error("operator snapshot wrote a secret to the store")
		}
	})

	t.Run("feature_off_still_blanks", func(t *testing.T) {
		pk := mustUpsert(t, env.Services.Devices, tA, "dfs-dev-3", "", "", "", "")
		content := `{"wifi":{"networks":[{"ssid":"home","password":"pw"}]}}`
		if err := env.Services.DeviceFiles.UpsertFromDevice(ctx, tA, pk, "config.json", content, "sha-off", "pull", nil); err != nil {
			t.Fatalf("UpsertFromDevice feature off: %v", err)
		}
		latest, err := env.Services.DeviceFiles.Latest(ctx, tA, pk, "config.json")
		if err != nil || latest == nil || strings.Contains(latest.Content, `"pw"`) {
			t.Fatalf("feature-off snapshot = %v, %v, want blanked", latest, err)
		}
	})
}
