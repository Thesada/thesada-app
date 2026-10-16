package migrations

import "testing"

func TestConcurrentIndexNames_ReadsTheBuiltName(t *testing.T) {
	body := "-- no-transaction\nCREATE INDEX CONCURRENTLY IF NOT EXISTS device_alerts_open_absence_idx\n    ON device_alerts (device_pk)\n"
	got := concurrentIndexNames(body)
	if len(got) != 1 || got[0] != "device_alerts_open_absence_idx" {
		t.Fatalf("names = %v", got)
	}
}
