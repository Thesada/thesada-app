package ratelimit

import (
	"context"
	"testing"
	"time"
)

// TestLimiter_AllowUnderCap asserts that hits inside the window pass while
// the cap is unreached.
func TestLimiter_AllowUnderCap(t *testing.T) {
	l := New(time.Second, 3)
	for i := 0; i < 3; i++ {
		if !l.Allow("a") {
			t.Fatalf("hit %d should be allowed under cap=3", i+1)
		}
	}
	if l.Allow("a") {
		t.Fatalf("hit 4 must be blocked once cap=3 is reached")
	}
}

// TestLimiter_KeysIsolated asserts that hits on key A do not consume the
// budget of key B.
func TestLimiter_KeysIsolated(t *testing.T) {
	l := New(time.Second, 1)
	if !l.Allow("a") {
		t.Fatal("first hit on a must pass")
	}
	if l.Allow("a") {
		t.Fatal("second hit on a must block")
	}
	if !l.Allow("b") {
		t.Fatal("b must have an independent budget")
	}
}

// TestLimiter_SweepDeletesEmptyKeys is the sweep contract test - the map
// must not grow unbounded across the process lifetime. Sweep with a future
// `now` past the window removes any key whose timestamps are all expired.
func TestLimiter_SweepDeletesEmptyKeys(t *testing.T) {
	l := New(50*time.Millisecond, 5)
	l.Allow("alice")
	l.Allow("bob")
	l.Allow("alice") // alice has 2 hits, bob has 1

	if got := len(l.hits); got != 2 {
		t.Fatalf("pre-sweep: want 2 keys, got %d", got)
	}

	// Anchor sweep at now + 1h - every recorded hit is far past the 50 ms
	// window so every entry should drop.
	deleted := l.sweep(time.Now().Add(time.Hour))
	if deleted != 2 {
		t.Fatalf("sweep should have deleted 2 keys, got %d", deleted)
	}
	if got := len(l.hits); got != 0 {
		t.Fatalf("post-sweep: want 0 keys, got %d", got)
	}
}

// TestLimiter_SweepKeepsLiveEntries asserts that the sweep does NOT delete
// keys with at least one hit still inside the window.
func TestLimiter_SweepKeepsLiveEntries(t *testing.T) {
	l := New(time.Hour, 5)
	l.Allow("alice")

	// Sweep anchored at now - the hit is fresh, alice must survive.
	deleted := l.sweep(time.Now())
	if deleted != 0 {
		t.Fatalf("sweep should not delete live keys, got %d deleted", deleted)
	}
	if _, ok := l.hits["alice"]; !ok {
		t.Fatalf("alice must still be in the map")
	}
}

// TestLimiter_StartSweeperHonoursContext - the goroutine must exit when ctx
// is cancelled. Spin one up with a tight window, cancel, and wait on the done
// channel so the assertion is deterministic. Sleeping instead is racy: after
// cancel the select can still pick a buffered ticker tick and run one more
// sweep, which would delete the sentinel even though shutdown is correct.
func TestLimiter_StartSweeperHonoursContext(t *testing.T) {
	l := New(10*time.Millisecond, 5)
	ctx, cancel := context.WithCancel(context.Background())
	done := l.StartSweeper(ctx)
	// Let the ticker fire a couple of times then cancel and wait for exit.
	time.Sleep(30 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("sweeper goroutine did not exit within 1s of cancel")
	}
	// Goroutine is gone; a stale key dropped now must never be swept.
	l.mu.Lock()
	l.hits["sentinel"] = []time.Time{time.Now().Add(-time.Hour)}
	l.mu.Unlock()
	time.Sleep(30 * time.Millisecond)
	l.mu.Lock()
	_, present := l.hits["sentinel"]
	l.mu.Unlock()
	if !present {
		t.Fatalf("sentinel was swept - sweeper goroutine did not exit on cancel")
	}
}
