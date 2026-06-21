// Package buildinfo exposes build-time metadata injected via -ldflags so
// runtime code (admin debug page, /healthz, logs) can report what version
// of thesada-app is actually running. Defaults are "dev" so `go run` and
// `go test` still produce sensible output without ldflags.
package buildinfo

import (
	"runtime"
	"time"
)

// These are populated by the linker. Do not write to them at runtime.
//
//	-X thesada.app/app/pkg/buildinfo.Version=v1.2.3
//	-X thesada.app/app/pkg/buildinfo.Commit=abc1234
//	-X thesada.app/app/pkg/buildinfo.BuildTime=2026-04-28T12:34:56Z
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// startedAt records process start; used to compute uptime on the debug page.
var startedAt = time.Now()

// StartedAt returns the time the process started.
// in: none. out: process start timestamp.
func StartedAt() time.Time { return startedAt }

// Uptime returns wall-clock seconds since process start.
// in: none. out: time.Duration since startedAt.
func Uptime() time.Duration { return time.Since(startedAt) }

// String returns a single-line human-readable summary suitable for log
// banners.
// in: none. out: e.g. "thesada-app v1.2.3 (commit abc1234, built 2026-04-28T12:34:56Z, go1.25.0 linux/amd64)".
func String() string {
	return "thesada-app " + Version +
		" (commit " + Commit +
		", built " + BuildTime +
		", " + runtime.Version() +
		" " + runtime.GOOS + "/" + runtime.GOARCH + ")"
}
