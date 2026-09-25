//go:build integration

package service_test

import (
	"context"
	"testing"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

func TestDeviceRuleWorkspacesService(t *testing.T) {
	env := servicetest.Start(t)
	rw := env.Services.RuleWorkspaces
	dev := env.Services.Devices
	ctx := context.Background()

	const tA, tB = "rw-a", "rw-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	t.Run("Save_Latest_History", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "rw-dev-1", "", "", "", "")
		sha1, err := rw.Save(ctx, tA, pk, "rules.lua", `{"blocks":{"languageVersion":0}}`, "-- lua v1\n", "editor", nil)
		if err != nil {
			t.Fatalf("Save v1: %v", err)
		}
		if sha1 == "" {
			t.Fatal("expected non-empty sha")
		}
		got, err := rw.Latest(ctx, tA, pk, "rules.lua")
		if err != nil || got == nil {
			t.Fatalf("Latest = %v err %v", got, err)
		}
		if got.LuaContent != "-- lua v1\n" || got.WorkspaceJSON == "" || got.LuaSHA256 != sha1 {
			t.Errorf("Latest mismatch: %+v", got)
		}

		sha2, err := rw.Save(ctx, tA, pk, "rules.lua", `{"blocks":{"languageVersion":1}}`, "-- lua v2\n", "push", nil)
		if err != nil {
			t.Fatalf("Save v2: %v", err)
		}
		if sha2 == sha1 {
			t.Error("lua content change should change sha")
		}
		hist, err := rw.History(ctx, tA, pk, "rules.lua", 10)
		if err != nil || len(hist) != 2 {
			t.Fatalf("History = %d err %v, want 2", len(hist), err)
		}
		if hist[0].LuaSHA256 != sha2 || hist[0].PrevSHA256 == nil || *hist[0].PrevSHA256 != sha1 {
			t.Errorf("newest hist sha=%q prev=%v, want %q/%q", hist[0].LuaSHA256, hist[0].PrevSHA256, sha2, sha1)
		}
	})

	t.Run("Latest_missing", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "rw-dev-missing", "", "", "", "")
		got, err := rw.Latest(ctx, tA, pk, "rules.lua")
		if err != nil || got != nil {
			t.Errorf("Latest missing = %v err %v, want nil nil", got, err)
		}
	})

	t.Run("invalid_slot_rejected", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "rw-dev-badslot", "", "", "", "")
		if _, err := rw.Save(ctx, tA, pk, "evil.lua", "{}", "", "editor", nil); err == nil {
			t.Fatal("expected invalid slot error")
		}
		if !service.ValidRuleSlot("main.lua") {
			t.Fatal("main.lua should be valid")
		}
		if _, err := rw.Save(ctx, tA, pk, "main.lua", `{"ok":true}`, "-- main\n", "editor", nil); err != nil {
			t.Fatalf("Save main.lua: %v", err)
		}
	})

	t.Run("RLS_tenant_isolation", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "rw-iso", "", "", "", "")
		if _, err := rw.Save(ctx, tA, pk, "rules.lua", `{"secret":true}`, "-- secret\n", "editor", nil); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if got, err := rw.Latest(ctx, tB, pk, "rules.lua"); err != nil || got != nil {
			t.Errorf("cross-tenant Latest = %v err %v, want nil", got, err)
		}
		if h, err := rw.History(ctx, tB, pk, "rules.lua", 10); err != nil || len(h) != 0 {
			t.Errorf("cross-tenant History = %v err %v, want empty", h, err)
		}
	})
}
