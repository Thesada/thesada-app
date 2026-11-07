package safego_test

import (
	"strings"
	"testing"

	"thesada.app/app/pkg/safego"
	"thesada.app/app/pkg/safego/safegotest"
)

// panicBoom is a named frame that only a stack taken before unwinding holds.
func panicBoom() { panic("boom") }

func TestRun_PanicIsLoggedWithSiteValueStackAndAttrs(t *testing.T) {
	log := safegotest.Capture(t)
	if !safego.Run("test.run", panicBoom, "device", "dev-1") {
		t.Fatal("Run reported no panic")
	}
	rec := log.WaitPanic(t, "test.run")
	if rec["level"] != "ERROR" || rec["panic"] != "boom" || rec["device"] != "dev-1" {
		t.Fatalf("panic record = %v, want ERROR with panic=boom device=dev-1", rec)
	}
	if stack, _ := rec["stack"].(string); !strings.Contains(stack, "safego_test.panicBoom") {
		t.Fatalf("stack does not name the panicking frame: %q", stack)
	}
}

func TestRun_CleanReturnLogsNothing(t *testing.T) {
	log := safegotest.Capture(t)
	ran := false
	if safego.Run("test.clean", func() { ran = true }) {
		t.Fatal("Run reported a panic for a clean return")
	}
	if !ran || log.Find("goroutine.panic", "test.clean") != nil {
		t.Fatalf("ran=%v, want fn called and no panic line", ran)
	}
}

func TestRun_DeferredCleanupInsideFnStillRuns(t *testing.T) {
	safegotest.Capture(t)
	released := false
	safego.Run("test.defer", func() {
		defer func() { released = true }()
		panic("boom")
	})
	if !released {
		t.Fatal("a defer inside fn did not run before the recover")
	}
}

func TestGo_PanicOnTheGoroutineDoesNotCrash(t *testing.T) {
	log := safegotest.Capture(t)
	safego.Go("test.go", func() { panic("boom") })
	log.WaitPanic(t, "test.go")
}
