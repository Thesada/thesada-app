//go:build integration

package servicetest

import (
	"context"
	"errors"
	"testing"

	"github.com/containerd/errdefs"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const readyLine = "database system is ready to accept connections"

// echoReadyTwice is an entrypoint that logs the ready line twice and exits.
var echoReadyTwice = testcontainers.WithEntrypoint("sh", "-c", "echo '"+readyLine+"'; echo '"+readyLine+"'")

// TestStartOnce_PortReadFailureTerminates: a container that passes its wait and
// is gone by the port read fails the start and is removed.
func TestStartOnce_PortReadFailureTerminates(t *testing.T) {
	var ctr *postgres.PostgresContainer
	_, err := startOnce(t, func(ctx context.Context, img string, opts ...testcontainers.ContainerCustomizer) (*postgres.PostgresContainer, error) {
		var err error
		ctr, err = postgres.Run(ctx, img, append(opts, echoReadyTwice,
			testcontainers.WithWaitStrategy(wait.ForExit()))...)
		testcontainers.CleanupContainer(t, ctr)
		return ctr, err
	})
	if !errdefs.IsNotFound(err) {
		t.Fatalf("want the port read to fail the start, got: %v", err)
	}
	if ctr == nil {
		t.Fatal("run returned no container")
	}
	if st, serr := ctr.State(context.Background()); serr == nil {
		t.Fatalf("failed start left the container behind, status %q", st.Status)
	}
}

// TestStartPostgres_RetriesFailedStart: a start that fails on the port read is
// replaced by a fresh one, and the pool from it works.
func TestStartPostgres_RetriesFailedStart(t *testing.T) {
	orig := startFn
	t.Cleanup(func() { startFn = orig })
	calls := 0
	startFn = func(t *testing.T) (string, error) {
		calls++
		if calls == 1 {
			return "", errors.New(`port "5432/tcp" not found`)
		}
		return orig(t)
	}

	super, _ := StartPostgres(t)
	if calls != 2 {
		t.Fatalf("start calls = %d, want 2", calls)
	}
	if err := super.Ping(context.Background()); err != nil {
		t.Fatalf("ping pool from the retried start: %v", err)
	}
}

// TestStartRetry_ReplacesFailedStartUpToCap: a failed start, as when 5432 is
// gone by the port read, gets a fresh one, and the attempts stay capped.
func TestStartRetry_ReplacesFailedStartUpToCap(t *testing.T) {
	notMapped := errors.New(`port "5432/tcp" not found`)
	calls := 0
	url, err := startRetry(t, func() (string, error) {
		calls++
		if calls < startAttempts {
			return "", notMapped
		}
		return "postgres://ok", nil
	})
	if err != nil || url != "postgres://ok" || calls != startAttempts {
		t.Fatalf("last attempt should start: calls=%d url=%q err=%v", calls, url, err)
	}

	calls = 0
	_, err = startRetry(t, func() (string, error) {
		calls++
		return "", notMapped
	})
	if !errors.Is(err, notMapped) || calls != startAttempts {
		t.Fatalf("want %d capped attempts and the last error: calls=%d err=%v", startAttempts, calls, err)
	}
}
