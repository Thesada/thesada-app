//go:build integration

// A bare legacy wifi.password device row is re-keyed once to wifi.password:<primary SSID>
// and is inert afterwards (Q2, Q3).
//
//	go test -tags integration -run TestLegacyWifi ./pkg/service/...
package service_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// legacyEnv is a KEK-on service bundle and its helpers for the legacy WiFi tests.
type legacyEnv struct {
	env  *servicetest.Env
	svcs *service.Services
	t    *testing.T
}

const legacyTenant = "lwf-a"

func newLegacyEnv(t *testing.T) *legacyEnv {
	env := servicetest.Start(t)
	cfg := *env.Cfg
	cfg.DeviceConfigKEK = testKEK
	svcs, err := service.New(&cfg, env.Pools)
	if err != nil {
		t.Fatalf("service.New with KEK: %v", err)
	}
	env.SeedTenant(t, legacyTenant)
	return &legacyEnv{env: env, svcs: svcs, t: t}
}

func (l *legacyEnv) device(id string) uuid.UUID {
	l.t.Helper()
	pk := mustUpsert(l.t, l.svcs.Devices, legacyTenant, id, "", "", "", "")
	if err := l.svcs.Secrets.PlantLegacyWifi(context.Background(), legacyTenant, pk, "legacy-pw"); err != nil {
		l.t.Fatalf("plant legacy row: %v", err)
	}
	return pk
}

func (l *legacyEnv) read(pk uuid.UUID, content string) {
	l.t.Helper()
	ctx := context.Background()
	at, err := l.svcs.DeviceFiles.ReadStart(ctx, legacyTenant)
	if err != nil {
		l.t.Fatalf("ReadStart: %v", err)
	}
	if _, err := l.svcs.DeviceFiles.UpsertFromDevice(ctx, legacyTenant, pk, "config.json", content, "sha", "drift", nil, at); err != nil {
		l.t.Fatalf("UpsertFromDevice: %v", err)
	}
}

func (l *legacyEnv) reveal(pk uuid.UUID, field string) (string, bool) {
	l.t.Helper()
	v, found, err := l.svcs.Secrets.Reveal(context.Background(), legacyTenant, pk, field)
	if err != nil {
		l.t.Fatalf("Reveal %s: %v", field, err)
	}
	return v, found
}

// drop runs DropClearedWifi with a mark taken just before, as Clear on device does around the device clear.
func (l *legacyEnv) drop(pk uuid.UUID, field string) error {
	l.t.Helper()
	mark, err := l.svcs.Secrets.MarkWifiSecret(context.Background(), legacyTenant, pk, field)
	if err != nil {
		l.t.Fatalf("MarkWifiSecret %s: %v", field, err)
	}
	return l.svcs.Secrets.DropClearedWifi(context.Background(), legacyTenant, pk, field, mark)
}

func (l *legacyEnv) bare(pk uuid.UUID) bool {
	l.t.Helper()
	var n int
	if err := l.env.Super.QueryRow(context.Background(),
		`SELECT count(*) FROM device_config_secrets WHERE device_pk = $1 AND field = $2`,
		pk, service.LegacyWifiPassword).Scan(&n); err != nil {
		l.t.Fatal(err)
	}
	return n > 0
}

const homeAndPark = `{"wifi":{"networks":[{"ssid":"home","password":""},{"ssid":"park","password":""}]}}`

func TestLegacyWifi(t *testing.T) {
	l := newLegacyEnv(t)
	ctx := context.Background()

	t.Run("a_current_read_rekeys_the_bare_row_to_the_primary_ssid", func(t *testing.T) {
		pk := l.device("lwf-1")
		l.read(pk, homeAndPark)
		if v, found := l.reveal(pk, "wifi.password:home"); !found || v != "legacy-pw" {
			t.Errorf("wifi.password:home = %q (found %v), want the legacy value", v, found)
		}
		if _, found := l.reveal(pk, "wifi.password:park"); found {
			t.Error("the legacy value landed on a second SSID")
		}
		if l.bare(pk) {
			t.Error("the bare row survived the re-key")
		}
	})

	t.Run("a_read_keeps_the_per_ssid_row_and_drops_the_bare_one", func(t *testing.T) {
		pk := l.device("lwf-2")
		if err := l.svcs.Secrets.SetSecret(ctx, legacyTenant, pk, "wifi.password:home", "per-ssid"); err != nil {
			t.Fatal(err)
		}
		l.read(pk, homeAndPark)
		if v, _ := l.reveal(pk, "wifi.password:home"); v != "per-ssid" {
			t.Errorf("wifi.password:home = %q, want the per-SSID row kept", v)
		}
		if l.bare(pk) {
			t.Error("the bare duplicate survived")
		}
	})

	t.Run("a_read_without_networks_leaves_the_bare_row_inert", func(t *testing.T) {
		pk := l.device("lwf-3")
		l.read(pk, `{"device":{"name":"x"}}`)
		if !l.bare(pk) {
			t.Error("a read with no SSID deleted the bare row")
		}
	})

	t.Run("a_stale_read_rekeys_nothing", func(t *testing.T) {
		pk := l.device("lwf-4")
		at, err := l.svcs.DeviceFiles.ReadStart(ctx, legacyTenant)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.svcs.DeviceFiles.MarkConfigChanged(ctx, legacyTenant, pk); err != nil {
			t.Fatal(err)
		}
		if _, err := l.svcs.DeviceFiles.UpsertFromDevice(ctx, legacyTenant, pk, "config.json", homeAndPark, "sha", "drift", nil, at); err != nil {
			t.Fatal(err)
		}
		if !l.bare(pk) {
			t.Error("a stale read re-keyed the bare row")
		}
		if _, found := l.reveal(pk, "wifi.password:home"); found {
			t.Error("a stale read wrote wifi.password:home")
		}
	})

	t.Run("a_verified_clear_of_the_primary_drops_the_bare_row_too", func(t *testing.T) {
		pk := l.device("lwf-6")
		if err := l.svcs.DeviceFiles.Upsert(ctx, legacyTenant, pk, "config.json", homeAndPark, "sha", "read", nil); err != nil {
			t.Fatal(err)
		}
		if err := l.svcs.Secrets.SetSecret(ctx, legacyTenant, pk, "wifi.password:home", "per-ssid"); err != nil {
			t.Fatal(err)
		}
		if err := l.drop(pk, "wifi.password:home"); err != nil {
			t.Fatalf("DropClearedWifi: %v", err)
		}
		if l.bare(pk) {
			t.Error("the bare row survived a verified clear of the primary network")
		}
		if _, err := service.MigrateLegacyWifi(ctx, l.svcs.Secrets, l.svcs.Devices, l.svcs.DeviceFiles); err != nil {
			t.Fatal(err)
		}
		l.read(pk, homeAndPark)
		if _, found := l.reveal(pk, "wifi.password:home"); found {
			t.Error("a re-key brought the cleared password back")
		}
	})

	t.Run("a_verified_clear_without_a_stored_config_drops_the_bare_row", func(t *testing.T) {
		pk := l.device("lwf-8")
		if err := l.drop(pk, "wifi.password:home"); err != nil {
			t.Fatalf("DropClearedWifi: %v", err)
		}
		if l.bare(pk) {
			t.Error("the bare row survived a verified clear on a device with no stored config")
		}
		l.read(pk, homeAndPark)
		if _, found := l.reveal(pk, "wifi.password:home"); found {
			t.Error("a later read re-keyed the cleared password back")
		}
	})

	t.Run("a_verified_clear_with_no_networks_stored_drops_the_bare_row", func(t *testing.T) {
		pk := l.device("lwf-9")
		if err := l.svcs.DeviceFiles.Upsert(ctx, legacyTenant, pk, "config.json", `{"device":{"name":"x"}}`, "sha", "read", nil); err != nil {
			t.Fatal(err)
		}
		if err := l.drop(pk, "wifi.password:home"); err != nil {
			t.Fatalf("DropClearedWifi: %v", err)
		}
		if l.bare(pk) {
			t.Error("the bare row survived a verified clear on a device whose stored config names no network")
		}
	})

	t.Run("a_verified_clear_of_another_network_keeps_the_bare_row", func(t *testing.T) {
		pk := l.device("lwf-7")
		if err := l.svcs.DeviceFiles.Upsert(ctx, legacyTenant, pk, "config.json", homeAndPark, "sha", "read", nil); err != nil {
			t.Fatal(err)
		}
		if err := l.drop(pk, "wifi.password:park"); err != nil {
			t.Fatalf("DropClearedWifi: %v", err)
		}
		if !l.bare(pk) {
			t.Error("a clear of a second network deleted the primary's bare row")
		}
	})

	t.Run("a_password_saved_after_the_mark_is_kept", func(t *testing.T) {
		for id, before := range map[string]string{"lwf-10": "old", "lwf-11": ""} {
			pk := l.device(id)
			if before != "" {
				if err := l.svcs.Secrets.SetSecret(ctx, legacyTenant, pk, "wifi.password:home", before); err != nil {
					t.Fatal(err)
				}
			}
			mark, err := l.svcs.Secrets.MarkWifiSecret(ctx, legacyTenant, pk, "wifi.password:home")
			if err != nil {
				t.Fatal(err)
			}
			if err := l.svcs.Secrets.SetSecret(ctx, legacyTenant, pk, "wifi.password:home", "new"); err != nil {
				t.Fatal(err)
			}
			if err := l.svcs.Secrets.DropClearedWifi(ctx, legacyTenant, pk, "wifi.password:home", mark); !errors.Is(err, service.ErrWifiSecretChanged) {
				t.Errorf("row before %q: DropClearedWifi = %v, want ErrWifiSecretChanged", before, err)
			}
			if v, found := l.reveal(pk, "wifi.password:home"); !found || v != "new" {
				t.Errorf("row before %q: stored = %q found=%v, want the later save kept", before, v, found)
			}
		}
	})

	// A read during the clear re-keys the bare row to the cleared network. That is the same password, not a save.
	t.Run("a_rekey_during_the_clear_is_dropped", func(t *testing.T) {
		pk := l.device("lwf-12")
		mark, err := l.svcs.Secrets.MarkWifiSecret(ctx, legacyTenant, pk, "wifi.password:home")
		if err != nil {
			t.Fatal(err)
		}
		l.read(pk, homeAndPark)
		if v, _ := l.reveal(pk, "wifi.password:home"); v != "legacy-pw" {
			t.Fatalf("precondition: wifi.password:home = %q, want the re-keyed legacy value", v)
		}
		if err := l.svcs.Secrets.DropClearedWifi(ctx, legacyTenant, pk, "wifi.password:home", mark); err != nil {
			t.Errorf("DropClearedWifi = %v, want the re-keyed row dropped", err)
		}
		if _, found := l.reveal(pk, "wifi.password:home"); found {
			t.Error("the re-keyed legacy password survived a verified clear")
		}
		if l.bare(pk) {
			t.Error("the bare row is back")
		}
	})

	t.Run("a_rekey_then_a_new_save_during_the_clear_keeps_the_save", func(t *testing.T) {
		pk := l.device("lwf-13")
		mark, err := l.svcs.Secrets.MarkWifiSecret(ctx, legacyTenant, pk, "wifi.password:home")
		if err != nil {
			t.Fatal(err)
		}
		l.read(pk, homeAndPark)
		if err := l.svcs.Secrets.SetSecret(ctx, legacyTenant, pk, "wifi.password:home", "new"); err != nil {
			t.Fatal(err)
		}
		if err := l.svcs.Secrets.DropClearedWifi(ctx, legacyTenant, pk, "wifi.password:home", mark); !errors.Is(err, service.ErrWifiSecretChanged) {
			t.Errorf("DropClearedWifi = %v, want ErrWifiSecretChanged", err)
		}
		if v, found := l.reveal(pk, "wifi.password:home"); !found || v != "new" {
			t.Errorf("stored = %q found=%v, want the later save kept", v, found)
		}
	})

	t.Run("without_a_legacy_row_a_clear_drops_and_a_save_is_kept", func(t *testing.T) {
		for id, save := range map[string]bool{"lwf-14": false, "lwf-15": true} {
			pk := mustUpsert(t, l.svcs.Devices, legacyTenant, id, "", "", "", "")
			if err := l.svcs.Secrets.SetSecret(ctx, legacyTenant, pk, "wifi.password:home", "old"); err != nil {
				t.Fatal(err)
			}
			mark, err := l.svcs.Secrets.MarkWifiSecret(ctx, legacyTenant, pk, "wifi.password:home")
			if err != nil {
				t.Fatal(err)
			}
			want := error(nil)
			if save {
				want = service.ErrWifiSecretChanged
				if err := l.svcs.Secrets.SetSecret(ctx, legacyTenant, pk, "wifi.password:home", "new"); err != nil {
					t.Fatal(err)
				}
			}
			if err := l.svcs.Secrets.DropClearedWifi(ctx, legacyTenant, pk, "wifi.password:home", mark); !errors.Is(err, want) {
				t.Errorf("save %v: DropClearedWifi = %v, want %v", save, err, want)
			}
			if _, found := l.reveal(pk, "wifi.password:home"); found != save {
				t.Errorf("save %v: row kept = %v", save, found)
			}
		}
	})

	t.Run("set_secret_refuses_the_bare_field", func(t *testing.T) {
		pk := mustUpsert(t, l.svcs.Devices, legacyTenant, "lwf-5", "", "", "", "")
		if err := l.svcs.Secrets.SetSecret(ctx, legacyTenant, pk, service.LegacyWifiPassword, "x"); err == nil {
			t.Error("SetSecret accepted the bare wifi.password")
		}
		if err := l.svcs.Secrets.SetTenantSecret(ctx, legacyTenant, service.LegacyWifiPassword, "x"); err == nil {
			t.Error("SetTenantSecret accepted the bare wifi.password")
		}
	})

	t.Run("a_bare_row_is_not_an_override_for_provisioning", func(t *testing.T) {
		const tP = "lwf-prov"
		l.env.SeedTenant(t, tP)
		pk := mustUpsert(t, l.svcs.Devices, tP, "lwf-p1", "", "", "", "")
		if err := l.svcs.Secrets.PlantLegacyWifi(ctx, tP, pk, "legacy-pw"); err != nil {
			t.Fatal(err)
		}
		if _, err := l.env.Super.Exec(ctx, `UPDATE devices SET paired_at = now() WHERE id = $1`, pk); err != nil {
			t.Fatal(err)
		}
		if err := l.svcs.Secrets.SetTenantSecret(ctx, tP, "wifi.password:SiteNet", "site"); err != nil {
			t.Fatal(err)
		}
		targets, err := l.svcs.Secrets.ProvisionTargets(ctx, tP, "wifi.password:SiteNet")
		if err != nil || len(targets) != 1 || targets[0] != pk {
			t.Errorf("ProvisionTargets = %v, %v, want the device with only a bare row", targets, err)
		}
		counts, err := l.svcs.Secrets.ProvisionTargetCounts(ctx, tP)
		if err != nil || counts["wifi.password:SiteNet"] != 1 {
			t.Errorf("ProvisionTargetCounts = %v, %v, want 1", counts, err)
		}
	})
}

// TestLegacyWifiSweep: migrate-legacy-wifi re-keys from the stored snapshot, keeps a per-SSID
// row over the bare one, leaves a device without a snapshot inert, and is idempotent.
func TestLegacyWifiSweep(t *testing.T) {
	l := newLegacyEnv(t)
	ctx := context.Background()
	snapshot := func(pk uuid.UUID) {
		t.Helper()
		if err := l.svcs.DeviceFiles.Upsert(ctx, legacyTenant, pk, "config.json", homeAndPark, "sha", "read", nil); err != nil {
			t.Fatalf("Upsert snapshot: %v", err)
		}
	}
	rekeyed := l.device("lws-1")
	snapshot(rekeyed)
	dup := l.device("lws-2")
	snapshot(dup)
	if err := l.svcs.Secrets.SetSecret(ctx, legacyTenant, dup, "wifi.password:home", "per-ssid"); err != nil {
		t.Fatal(err)
	}
	inert := l.device("lws-3")

	sweep := func() service.LegacyWifiResult {
		t.Helper()
		res, err := service.MigrateLegacyWifi(ctx, l.svcs.Secrets, l.svcs.Devices, l.svcs.DeviceFiles)
		if err != nil {
			t.Fatalf("MigrateLegacyWifi: %v", err)
		}
		return res
	}
	if res := sweep(); res.Rekeyed != 1 || res.Duplicates != 1 || res.NoSSID != 1 || res.Undecryptable != 0 {
		t.Fatalf("first sweep = %+v, want 1 rekeyed, 1 duplicate, 1 without SSID", res)
	}
	if v, _ := l.reveal(rekeyed, "wifi.password:home"); v != "legacy-pw" || l.bare(rekeyed) {
		t.Errorf("rekeyed device: home = %q, bare left %v, want legacy-pw and no bare row", v, l.bare(rekeyed))
	}
	if v, _ := l.reveal(dup, "wifi.password:home"); v != "per-ssid" || l.bare(dup) {
		t.Errorf("duplicate device: home = %q, bare left %v, want per-ssid and no bare row", v, l.bare(dup))
	}
	if !l.bare(inert) {
		t.Error("a device without a snapshot lost its bare row")
	}
	status, err := l.svcs.Secrets.Status(ctx, legacyTenant, inert)
	if err != nil || !status[service.LegacyWifiPassword] {
		t.Errorf("Status = %v, %v, want the inert bare row listed", status, err)
	}
	if res := sweep(); res.Rekeyed != 0 || res.Duplicates != 0 || res.NoSSID != 1 {
		t.Errorf("second sweep = %+v, want only the inert row again", res)
	}
}
