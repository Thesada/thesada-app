package alerts

import (
	"testing"
	"time"
)

func TestRetryBackoff_DoublesPerAttemptAndCaps(t *testing.T) {
	base := time.Minute
	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{0, time.Minute}, // defensive: pre-first-attempt input clamps to base
		{1, time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{5, 16 * time.Minute},
		{7, 64 * time.Minute},
		{50, 64 * time.Minute}, // cap: a runaway attempt count never overflows
	}
	for _, c := range cases {
		if got := retryBackoff(base, c.attempts); got != c.want {
			t.Errorf("retryBackoff(1m, %d) = %v, want %v", c.attempts, got, c.want)
		}
	}
}
