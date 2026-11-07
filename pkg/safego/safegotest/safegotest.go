// Package safegotest captures the default slog output so a test can wait for
// a guarded site to log its goroutine.panic line.
package safegotest

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"
	"time"
)

// Log is a slog sink that goroutines may write to concurrently.
type Log struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

// Write appends one encoded slog record.
// in: encoded record. out: bytes written, error.
func (l *Log) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

// Capture routes the default slog logger into a Log until the test ends.
// Callers must not run in parallel with other tests that swap the default.
// in: t. out: the Log.
func Capture(t *testing.T) *Log {
	t.Helper()
	l := &Log{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(l, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return l
}

// WaitPanic blocks until a goroutine.panic line for site is logged.
// in: t, site name. out: that record's fields (fails the test after 5 s).
func (l *Log) WaitPanic(t *testing.T, site string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rec := l.Find("goroutine.panic", site); rec != nil {
			return rec
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no goroutine.panic logged for site %q", site)
	return nil
}

// Find returns the first record with this message and site, or nil.
// in: message, site name. out: record fields or nil.
func (l *Log) Find(msg, site string) map[string]any {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, line := range bytes.Split(l.buf.Bytes(), []byte("\n")) {
		var rec map[string]any
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		if rec["msg"] == msg && rec["site"] == site {
			return rec
		}
	}
	return nil
}
