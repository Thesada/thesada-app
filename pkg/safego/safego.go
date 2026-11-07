// Package safego runs work that device or request input can reach, so a
// panic in it is logged as goroutine.panic instead of killing the process.
package safego

import (
	"log/slog"
	"runtime/debug"
)

// Go starts fn on a new goroutine under Run.
// in: site name, fn, extra slog key/value pairs. out: none.
func Go(site string, fn func(), attrs ...any) {
	go Run(site, fn, attrs...)
}

// Run calls fn and turns a panic into one goroutine.panic line at error,
// with the panic value and stack. Deferred calls inside fn still run first.
// in: site name, fn, extra slog key/value pairs. out: true when fn panicked.
func Run(site string, fn func(), attrs ...any) (panicked bool) {
	defer func() {
		if rec := recover(); rec != nil {
			panicked = true
			args := append([]any{"site", site, "panic", rec, "stack", string(debug.Stack())}, attrs...)
			slog.Error("goroutine.panic", args...)
		}
	}()
	fn()
	return false
}
