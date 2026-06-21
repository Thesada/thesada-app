//go:build integration

// DeviceFilesService integration tests. Canonical-state
// upsert with history-on-change, latest/sha reads, paginated history, drift
// observation, retention prune, and RLS isolation. (The old
// ConfigSnapshotService is dead code slated for deletion and is not
// tested.)
//
//	go test -tags integration -run TestDeviceFilesService ./pkg/service/...
package service_test

import (
	"context"
	"testing"

	"thesada.app/app/pkg/service/servicetest"
)

func TestDeviceFilesService(t *testing.T) {
	env := servicetest.Start(t)
	df := env.Services.DeviceFiles
	dev := env.Services.Devices
	ctx := context.Background()

	const tA, tB = "df-a", "df-b"
	env.SeedTenant(t, tA)
	env.SeedTenant(t, tB)

	t.Run("Upsert_Latest_and_history_on_change", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "df-dev-1", "", "", "", "")
		const path = "/config.json"

		if err := df.Upsert(ctx, tA, pk, path, "v1", "sha1", "pull", nil); err != nil {
			t.Fatalf("Upsert v1: %v", err)
		}
		latest, err := df.Latest(ctx, tA, pk, path)
		if err != nil || latest == nil || latest.Content != "v1" || latest.SHA256 != "sha1" {
			t.Fatalf("Latest after v1 = %v err %v", latest, err)
		}
		if sha, _ := df.LatestSHA(ctx, tA, pk, path); sha != "sha1" {
			t.Errorf("LatestSHA = %q, want sha1", sha)
		}

		// Different sha -> canonical updated + new history row.
		if err := df.Upsert(ctx, tA, pk, path, "v2", "sha2", "pull", nil); err != nil {
			t.Fatalf("Upsert v2: %v", err)
		}
		hist, err := df.History(ctx, tA, pk, path, 10)
		if err != nil || len(hist) != 2 {
			t.Fatalf("History = %d (err %v), want 2", len(hist), err)
		}
		if hist[0].SHA256 != "sha2" || hist[0].PrevSHA256 == nil || *hist[0].PrevSHA256 != "sha1" {
			t.Errorf("newest history = sha %q prev %v, want sha2/sha1", hist[0].SHA256, hist[0].PrevSHA256)
		}

		// Same sha, non-operator source -> no new history.
		if err := df.Upsert(ctx, tA, pk, path, "v2", "sha2", "pull", nil); err != nil {
			t.Fatalf("Upsert dup: %v", err)
		}
		if h, _ := df.History(ctx, tA, pk, path, 10); len(h) != 2 {
			t.Errorf("history after dup pull = %d, want still 2", len(h))
		}
		// Same sha but operator "write" -> always logged.
		if err := df.Upsert(ctx, tA, pk, path, "v2", "sha2", "write", nil); err != nil {
			t.Fatalf("Upsert write: %v", err)
		}
		if h, _ := df.History(ctx, tA, pk, path, 10); len(h) != 3 {
			t.Errorf("history after operator write = %d, want 3", len(h))
		}
	})

	t.Run("Latest_LatestSHA_missing", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "df-dev-missing", "", "", "", "")
		if got, err := df.Latest(ctx, tA, pk, "/none"); err != nil || got != nil {
			t.Errorf("Latest missing = %v err %v, want nil nil", got, err)
		}
		if sha, err := df.LatestSHA(ctx, tA, pk, "/none"); err != nil || sha != "" {
			t.Errorf("LatestSHA missing = %q err %v, want empty", sha, err)
		}
	})

	t.Run("HistoryPage_paginates_with_total", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "df-dev-page", "", "", "", "")
		const path = "/script.lua"
		for i, sha := range []string{"a", "b", "c", "d"} {
			content := string(rune('0' + i))
			if err := df.Upsert(ctx, tA, pk, path, content, sha, "pull", nil); err != nil {
				t.Fatalf("Upsert %s: %v", sha, err)
			}
		}
		page, total, err := df.HistoryPage(ctx, tA, pk, path, 2, 0)
		if err != nil {
			t.Fatalf("HistoryPage: %v", err)
		}
		if total != 4 {
			t.Errorf("total = %d, want 4", total)
		}
		if len(page) != 2 || page[0].SHA256 != "d" {
			t.Errorf("page 0 = %d rows, first %v, want 2 rows newest 'd'", len(page), page)
		}
		page2, _, _ := df.HistoryPage(ctx, tA, pk, path, 2, 2)
		if len(page2) != 2 || page2[0].SHA256 != "b" {
			t.Errorf("page 1 first = %v, want 'b'", page2)
		}
	})

	t.Run("PruneHistory_keeps_retention", func(t *testing.T) {
		env.Cfg.ConfigSnapshotRetention = 2 // service shares this cfg pointer
		pk := mustUpsert(t, dev, tA, "df-dev-prune", "", "", "", "")
		const path = "/p.json"
		for _, sha := range []string{"p1", "p2", "p3", "p4"} {
			if err := df.Upsert(ctx, tA, pk, path, sha, sha, "pull", nil); err != nil {
				t.Fatalf("Upsert %s: %v", sha, err)
			}
		}
		if err := df.PruneHistory(ctx, tA, pk, path); err != nil {
			t.Fatalf("PruneHistory: %v", err)
		}
		h, _ := df.History(ctx, tA, pk, path, 50)
		if len(h) != 2 {
			t.Errorf("history after prune = %d, want 2 (retention)", len(h))
		}
	})

	t.Run("RecordObservation", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "df-dev-obs", "", "", "", "")
		if err := df.RecordObservation(ctx, tA, pk, "/o.json", "obs-sha"); err != nil {
			t.Fatalf("RecordObservation: %v", err)
		}
		var n int
		if err := env.Super.QueryRow(ctx,
			`SELECT count(*) FROM device_file_observations WHERE device_pk = $1`, pk).Scan(&n); err != nil {
			t.Fatalf("count observations: %v", err)
		}
		if n != 1 {
			t.Errorf("observations = %d, want 1", n)
		}
	})

	t.Run("RLS_tenant_isolation", func(t *testing.T) {
		pk := mustUpsert(t, dev, tA, "df-iso", "", "", "", "")
		if err := df.Upsert(ctx, tA, pk, "/iso", "secret", "shax", "pull", nil); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
		if got, err := df.Latest(ctx, tB, pk, "/iso"); err != nil || got != nil {
			t.Errorf("cross-tenant Latest = %v err %v, want nil", got, err)
		}
		if h, err := df.History(ctx, tB, pk, "/iso", 10); err != nil || len(h) != 0 {
			t.Errorf("cross-tenant History = %v err %v, want empty", h, err)
		}
	})
}
