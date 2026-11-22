//go:build integration

package service_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service/servicetest"
)

// TestEndConfigChange_KeepsALaterWindow: a close that comes after another mark, as a command that
// outlived its claim does, leaves the later window in place. A close with no later mark ends its own.
func TestEndConfigChange_KeepsALaterWindow(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	df := env.Services.DeviceFiles
	const tenant = "cfg-window"
	env.SeedTenant(t, tenant)

	stamp := func(pk uuid.UUID) *time.Time {
		t.Helper()
		var at *time.Time
		if err := env.Super.QueryRow(ctx, `SELECT config_changed_at FROM devices WHERE id = $1`, pk).Scan(&at); err != nil {
			t.Fatalf("read config_changed_at: %v", err)
		}
		return at
	}
	cases := []struct {
		name          string
		first, second time.Duration
	}{
		{"later window ends after the first", time.Minute, 15 * time.Minute},
		{"later window ends inside the first", time.Hour, 15 * time.Minute},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pk := mustUpsert(t, env.Services.Devices, tenant, "win-"+string(rune('a'+i)), "", "", "", "")
			first, err := df.MarkConfigChanging(ctx, tenant, pk, tc.first)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := df.MarkConfigChanging(ctx, tenant, pk, tc.second); err != nil {
				t.Fatal(err)
			}
			want := time.Now().Add(tc.second - time.Minute)
			if err := df.EndConfigChange(ctx, tenant, pk, first); err != nil {
				t.Fatal(err)
			}
			if at := stamp(pk); at == nil || at.Before(want) {
				t.Fatalf("config_changed_at = %v after the late close, want past %v", at, want)
			}
		})
	}

	t.Run("no later mark closes its own window", func(t *testing.T) {
		pk := mustUpsert(t, env.Services.Devices, tenant, "win-own", "", "", "", "")
		mark, err := df.MarkConfigChanging(ctx, tenant, pk, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		if err := df.EndConfigChange(ctx, tenant, pk, mark); err != nil {
			t.Fatal(err)
		}
		if at := stamp(pk); at == nil || at.After(time.Now().Add(time.Minute)) {
			t.Fatalf("config_changed_at = %v, want the window closed at about now", at)
		}
	})
}
