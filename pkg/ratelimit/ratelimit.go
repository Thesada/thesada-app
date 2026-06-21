// Package ratelimit is a tiny in-memory sliding-window limiter used to cap
// magic-link email creation. Keyed by a caller-supplied string (email or IP),
// it stores per-key event timestamps and trims them as new requests arrive.
// Not distributed, not persistent - fine for a single-binary deployment.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter tracks event timestamps per key within a fixed window.
type Limiter struct {
	window time.Duration
	max    int
	mu     sync.Mutex
	hits   map[string][]time.Time
}

// New constructs a limiter that allows at most max events per window per key.
// in: window, max events. out: ready *Limiter.
func New(window time.Duration, max int) *Limiter {
	return &Limiter{
		window: window,
		max:    max,
		hits:   make(map[string][]time.Time),
	}
}

// Allow records a hit for key at time.Now and reports whether the key is still
// under the cap. Callers should check the return and reject if false.
// in: key. out: true if allowed, false if rate exceeded.
func (l *Limiter) Allow(key string) bool {
	now := time.Now()
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	h := l.hits[key]
	kept := h[:0]
	for _, t := range h {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[key] = kept
		return false
	}
	kept = append(kept, now)
	l.hits[key] = kept
	return true
}

// sweep removes empty entries from the per-key map and refreshes surviving
// slices so the backing array can shrink. Separate from StartSweeper so unit
// tests can exercise a single tick without coordinating with a goroutine.
// in: now (the cutoff anchor; injected for deterministic tests).
// out: number of keys deleted.
func (l *Limiter) sweep(now time.Time) int {
	cutoff := now.Add(-l.window)
	l.mu.Lock()
	defer l.mu.Unlock()
	deleted := 0
	for k, hits := range l.hits {
		kept := hits[:0]
		for _, ts := range hits {
			if ts.After(cutoff) {
				kept = append(kept, ts)
			}
		}
		if len(kept) == 0 {
			delete(l.hits, k)
			deleted++
		} else {
			l.hits[k] = kept
		}
	}
	return deleted
}

// StartSweeper launches a goroutine that periodically removes empty entries
// from the per-key map. Allow trims expired timestamps but leaves the map key
// in place; over the lifetime of a long-running systemd unit each fresh IP /
// email accreted is one residual entry that never goes away. The sweep walks
// the map at the window cadence and deletes any key whose slice is empty
// post-trim, plus refreshes the slice for keys with surviving timestamps so
// the underlying array can shrink.
//
// Call once at app startup with a cancellable context tied to the shutdown
// signal. The goroutine exits cleanly when ctx is done.
// in: cancellable ctx. out: channel closed once the goroutine has exited
// (callers may ignore it; tests use it to synchronize on shutdown).
func (l *Limiter) StartSweeper(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(l.window)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				l.sweep(now)
			}
		}
	}()
	return done
}
