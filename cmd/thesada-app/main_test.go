package main

import (
	"context"
	"os"
	"regexp"
	"testing"
	"time"
)

// fakeHTTP blocks Shutdown until release closes, or until its ctx ends when
// release is nil (a server that never drains).
type fakeHTTP struct {
	called  chan struct{}
	release chan struct{}
}

func newFakeHTTP(release chan struct{}) *fakeHTTP {
	return &fakeHTTP{called: make(chan struct{}), release: release}
}

func (f *fakeHTTP) Shutdown(ctx context.Context) error {
	close(f.called)
	if f.release == nil {
		<-ctx.Done()
		return ctx.Err()
	}
	select {
	case <-f.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// fakeJobs blocks DrainJobs until release closes or its ctx ends.
type fakeJobs struct{ release chan struct{} }

func (f *fakeJobs) DrainJobs(ctx context.Context) error {
	select {
	case <-f.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// closed returns an already closed channel: the fake finishes at once.
func closed() chan struct{} {
	c := make(chan struct{})
	close(c)
	return c
}

// runShutdown runs gracefulShutdown in the background. out: closed on return.
func runShutdown(h *fakeHTTP, j *fakeJobs, httpBudget, jobBudget time.Duration) <-chan struct{} {
	returned := make(chan struct{})
	go func() {
		gracefulShutdown(h, j, httpBudget, jobBudget)
		close(returned)
	}()
	return returned
}

// mustBlock fails when returned closes within 100 ms.
func mustBlock(t *testing.T, returned <-chan struct{}, what string) {
	t.Helper()
	select {
	case <-returned:
		t.Fatalf("gracefulShutdown returned while %s", what)
	case <-time.After(100 * time.Millisecond):
	}
}

// mustReturnWithin fails when returned does not close within d.
func mustReturnWithin(t *testing.T, returned <-chan struct{}, d time.Duration) {
	t.Helper()
	select {
	case <-returned:
	case <-time.After(d):
		t.Fatalf("gracefulShutdown did not return within %v", d)
	}
}

func TestGracefulShutdown_WaitsForJobs(t *testing.T) {
	h, j := newFakeHTTP(closed()), &fakeJobs{release: make(chan struct{})}
	returned := runShutdown(h, j, 10*time.Second, 10*time.Second)
	<-h.called
	mustBlock(t, returned, "a job was still running")
	close(j.release)
	mustReturnWithin(t, returned, 5*time.Second)
}

func TestGracefulShutdown_WaitsForTheHTTPDrain(t *testing.T) {
	release := make(chan struct{})
	h, j := newFakeHTTP(release), &fakeJobs{release: closed()}
	returned := runShutdown(h, j, 10*time.Second, 10*time.Second)
	<-h.called
	mustBlock(t, returned, "the HTTP drain was still running")
	close(release)
	mustReturnWithin(t, returned, 5*time.Second)
}

func TestGracefulShutdown_JobsGetTheJobBudget(t *testing.T) {
	h, j := newFakeHTTP(closed()), &fakeJobs{release: make(chan struct{})}
	mustReturnWithin(t, runShutdown(h, j, 10*time.Second, 50*time.Millisecond), time.Second)
}

func TestGracefulShutdown_HTTPGetsTheHTTPBudget(t *testing.T) {
	h, j := newFakeHTTP(nil), &fakeJobs{release: closed()}
	mustReturnWithin(t, runShutdown(h, j, 50*time.Millisecond, 10*time.Second), time.Second)
}

func TestShutdownBudgets_FitTheStopGracePeriod(t *testing.T) {
	compose, err := os.ReadFile("../../deploy/docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`stop_grace_period:\s*(\d+s)`).FindSubmatch(compose)
	if m == nil {
		t.Fatal("no stop_grace_period in deploy/docker-compose.yml")
	}
	grace, err := time.ParseDuration(string(m[1]))
	if err != nil {
		t.Fatal(err)
	}
	if httpBudget > jobBudget || jobBudget >= grace {
		t.Fatalf("budgets http=%v job=%v must sit under the %v stop_grace_period", httpBudget, jobBudget, grace)
	}
}
