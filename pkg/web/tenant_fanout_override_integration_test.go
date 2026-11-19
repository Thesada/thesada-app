//go:build integration

// A tenant default fan-out re-checks each device's override at push time, under the device row
// lock an override write takes, so a device overridden after the target list was read is skipped.
//
//	go test -tags integration -run TestTenantFanOutOverride ./pkg/web/...
package web

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
)

func TestTenantFanOutOverride(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	ctx := context.Background()

	const tenant = "fanout-ovr"
	const field = "wifi.password:site"
	env.SeedTenant(t, tenant)
	if err := env.Services.Secrets.SetTenantSecret(ctx, tenant, field, "default"); err != nil {
		t.Fatal(err)
	}
	device := func(id string) (uuid.UUID, *mqtttest.FakeDevice) {
		t.Helper()
		prefix := "thesada/" + tenant + "/" + id
		d := seedDevice(t, env, tenant, id, prefix)
		if _, err := env.Super.Exec(ctx, `UPDATE devices SET paired_at = now() WHERE id = $1`, d.ID); err != nil {
			t.Fatal(err)
		}
		return d.ID, mqtttest.NewFakeDevice(t, broker, prefix)
	}
	targets := func(want uuid.UUID) []uuid.UUID {
		t.Helper()
		got, err := env.Services.Secrets.ProvisionTargets(ctx, tenant, field)
		if err != nil {
			t.Fatal(err)
		}
		for _, pk := range got {
			if pk == want {
				return []uuid.UUID{pk}
			}
		}
		t.Fatalf("ProvisionTargets = %v, want %s listed", got, want)
		return nil
	}

	t.Run("an_override_after_the_target_list_is_skipped", func(t *testing.T) {
		pk, fd := device("ovr1")
		fd.Handle("secret.set", func(string, []byte) []mqtttest.Response { return mqtttest.OK("stored") })
		list := targets(pk)
		if err := env.Services.Secrets.SetSecret(ctx, tenant, pk, field, "own"); err != nil {
			t.Fatal(err)
		}
		out := s.fanOutTenantSecret(ctx, tenant, field, "default", list)
		if out.Pushed != 0 || out.Unreachable != 0 || out.Rejected != 0 || out.Skipped != 0 {
			t.Errorf("fan-out = %+v, want the overridden device in no push bucket", out)
		}
		if n := fd.Calls("secret.set"); n != 0 {
			t.Errorf("secret.set calls = %d, want the default kept off an overridden device", n)
		}
	})

	t.Run("an_override_write_waits_for_a_running_push", func(t *testing.T) {
		pk, fd := device("ovr2")
		list := targets(pk)
		overrideDone := make(chan error, 1)
		var early atomic.Bool
		fd.Handle("secret.set", func(string, []byte) []mqtttest.Response {
			go func() { overrideDone <- env.Services.Secrets.SetSecret(ctx, tenant, pk, field, "own") }()
			select {
			case err := <-overrideDone:
				early.Store(true)
				overrideDone <- err
			case <-time.After(time.Second):
			}
			return mqtttest.OK("stored")
		})
		out := s.fanOutTenantSecret(ctx, tenant, field, "default", list)
		if out.Pushed != 1 {
			t.Fatalf("fan-out = %+v, want the device pushed", out)
		}
		if early.Load() {
			t.Error("an override write landed while the push for that device was running")
		}
		select {
		case err := <-overrideDone:
			if err != nil {
				t.Fatalf("override after the push: %v", err)
			}
		case <-time.After(15 * time.Second):
			t.Fatal("the override write never finished")
		}
		if v, _, err := env.Services.Secrets.Reveal(ctx, tenant, pk, field); err != nil || v != "own" {
			t.Errorf("override = %q, %v, want own kept after the push", v, err)
		}
	})
}
