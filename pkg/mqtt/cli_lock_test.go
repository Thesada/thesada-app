// Cheap unit tests for the CLI per-device lock + envelope wrapping. These
// do not touch the broker - they cover the in-process invariants the rest
// of pkg/mqtt depends on.
package mqtt

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"
)

// cliLockFor returns the same mutex for repeat lookups of the same prefix.
// Different prefixes must get distinct mutexes so concurrent CLI traffic
// against device A does not block device B.
func TestCliLockForIdentityAndIsolation(t *testing.T) {
	c := &Client{}

	a1 := c.cliLockFor("thesada/default/A")
	a2 := c.cliLockFor("thesada/default/A")
	b1 := c.cliLockFor("thesada/default/B")

	if a1 != a2 {
		t.Fatalf("repeat lookup returned different mutex for the same prefix")
	}
	if a1 == b1 {
		t.Fatalf("distinct prefixes share a mutex; would serialize unrelated devices")
	}
}

// cliLockFor is safe to call from many goroutines at once.
func TestCliLockForConcurrent(t *testing.T) {
	c := &Client{}

	var wg sync.WaitGroup
	var counter int
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := c.cliLockFor("thesada/default/X")
			m.Lock()
			counter++
			m.Unlock()
		}()
	}
	wg.Wait()
	if counter != 100 {
		t.Fatalf("counter %d, want 100 - lock did not serialize concurrent writers", counter)
	}
}

// A caller queued behind a held lock gives up at its own deadline, not the holder's.
func TestCliLockWaitEndsAtTheCallerDeadline(t *testing.T) {
	c := &Client{}
	l := c.cliLockFor("thesada/default/A")
	l.Lock()
	defer l.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := l.lockCtx(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lockCtx = %v, want the deadline", err)
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("waited %s for a 50 ms deadline", waited)
	}
}

// Envelope marshals into the exact shape firmware v1.4.5+ expects.
func TestCliEnvelopeShape(t *testing.T) {
	env := cliEnvelope{ReqID: "abc-123", Args: "/sd/log042.csv 0 256"}
	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got["req_id"] != "abc-123" {
		t.Fatalf("req_id mismatch: %v", got["req_id"])
	}
	if got["args"] != "/sd/log042.csv 0 256" {
		t.Fatalf("args mismatch: %v", got["args"])
	}
	// Firmware envelope contract: only req_id + args at top level. Extra
	// keys would be forwarded as Shell args literal and break commands.
	if len(got) != 2 {
		t.Fatalf("envelope has unexpected keys: %v", got)
	}
}

// CLIResponse parses req_id when firmware echoes it.
func TestCLIResponseReqID(t *testing.T) {
	raw := []byte(`{"cmd":"version","req_id":"r2","ok":true,"output":["thesada-fw v1.4.5"]}`)
	var resp CLIResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ReqID != "r2" {
		t.Fatalf("req_id not parsed: got %q", resp.ReqID)
	}
}

// CLIResponse stays valid when older firmware omits req_id.
func TestCLIResponseNoReqID(t *testing.T) {
	raw := []byte(`{"cmd":"version","ok":true,"output":["thesada-fw v1.4.4"]}`)
	var resp CLIResponse
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if resp.ReqID != "" {
		t.Fatalf("expected empty req_id, got %q", resp.ReqID)
	}
}
