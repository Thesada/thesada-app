package service

import "testing"

// Firmware below 1.4.5 does not echo req_id, so it and an unknown version are below the floor.
func TestFirmwareMeetsFloor(t *testing.T) {
	cases := []struct {
		version *string
		want    bool
	}{
		{fwv("1.4.5"), true},
		{fwv("v1.4.5"), true},
		{fwv("1.4.10"), true},
		{fwv("1.5.0"), true},
		{fwv("26.11.1"), true},
		{fwv("26.11.1-dev"), true},
		{fwv("1.4.4"), false},
		{fwv("1.3.9"), false},
		{fwv("v1.4.4"), false},
		{fwv("0.9.99"), false},
		{nil, false},
		{fwv(""), false},
		{fwv("1.4"), false},
		{fwv("1.4.x"), false},
		{fwv("1.+4.5"), false},
		{fwv("unknown"), false},
	}
	for _, tc := range cases {
		if got := FirmwareMeetsFloor(tc.version); got != tc.want {
			name := "<nil>"
			if tc.version != nil {
				name = *tc.version
			}
			t.Errorf("FirmwareMeetsFloor(%q) = %v, want %v", name, got, tc.want)
		}
	}
}

func fwv(s string) *string { return &s }
