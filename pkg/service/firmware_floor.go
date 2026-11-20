package service

import (
	"strconv"
	"strings"
)

// MinFirmwareVersion is the oldest firmware that echoes req_id, which every stored device reply needs.
const MinFirmwareVersion = "1.4.5"

// FirmwareMeetsFloor reports whether a device-reported version is MinFirmwareVersion or later.
// An unknown or unparsable version fails closed. in: reported version (nil when never reported). out: ok.
func FirmwareMeetsFloor(version *string) bool {
	if version == nil {
		return false
	}
	got, ok := parseFirmwareVersion(*version)
	if !ok {
		return false
	}
	floor, _ := parseFirmwareVersion(MinFirmwareVersion)
	for i := range got {
		if got[i] != floor[i] {
			return got[i] > floor[i]
		}
	}
	return true
}

// parseFirmwareVersion reads MAJOR.MINOR.PATCH or CalVer YY.0M.MICRO, an optional leading v,
// and drops a -pre or +build suffix. out: the three numbers, ok.
func parseFirmwareVersion(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, false
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 || p == "" || p[0] == '+' || p[0] == '-' {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
