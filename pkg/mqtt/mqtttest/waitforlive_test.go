//go:build integration

package mqtttest

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// TestWaitForLive_StuckFirstPingDoesNotStall: a ping sent before the client's
// connect lands blocks for the publish timeout, the next ping must still go out.
func TestWaitForLive_StuckFirstPingDoesNotStall(t *testing.T) {
	var sink func(string, []byte, bool, byte)
	var calls atomic.Int32
	register := func(_ string, s func(string, []byte, bool, byte)) (func(), error) {
		sink = s
		return func() {}, nil
	}
	publish := func(topic string, payload []byte, _ byte, _ bool) error {
		if calls.Add(1) == 1 {
			time.Sleep(5 * time.Second)
			return errors.New("publish not confirmed")
		}
		sink(topic, payload, false, 0)
		return nil
	}

	start := time.Now()
	WaitForLive(t, "thesada/__probe__/status", register, publish)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("WaitForLive took %v behind one stuck ping, want under 2s", d)
	}
}
