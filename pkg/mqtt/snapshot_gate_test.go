package mqtt

import (
	"testing"
	"time"
)

// A device that never completed pairing is on the shared onboarding
// credential, where firmware refuses fs.ls and config.dump. Snapshotting it
// produces one timeout per file and no data.
func TestSnapshotAllowedRejectsUnpairedDevice(t *testing.T) {
	if snapshotAllowed(nil) {
		t.Fatal("unpaired device (paired_at nil) must not be snapshotted")
	}
}

func TestSnapshotAllowedAcceptsPairedDevice(t *testing.T) {
	at := time.Now()
	if !snapshotAllowed(&at) {
		t.Fatal("paired device must be snapshotted")
	}
}

// paired_at is what the pair flow stamps; any non-nil value counts, including
// an old one. Freshness is not the gate here, existence is.
func TestSnapshotAllowedIgnoresPairingAge(t *testing.T) {
	old := time.Now().Add(-5 * 365 * 24 * time.Hour)
	if !snapshotAllowed(&old) {
		t.Fatal("a long-paired device must still be snapshotted")
	}
	zero := time.Time{}
	if !snapshotAllowed(&zero) {
		t.Fatal("non-nil paired_at must count even at the zero time")
	}
}
