package web

import "testing"

// The fraction keeps its leading zero: 1.05 MB is not 1.5 MB.
func TestHumanBytes_FractionLeadingZero(t *testing.T) {
	for n, want := range map[uint64]string{
		512:                      "512 B",
		1024 + 51:                "1.05 KB",
		1024*1024 + 52429:        "1.05 MB",
		3*1024*1024*1024 + 1<<29: "3.50 GB",
	} {
		if got := humanBytes(n); got != want {
			t.Errorf("humanBytes(%d) = %q, want %q", n, got, want)
		}
	}
}
