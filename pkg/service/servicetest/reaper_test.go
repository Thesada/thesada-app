//go:build integration

package servicetest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
)

// childMode makes this binary the reaper child: "hold" or "none".
const childMode = "SERVICETEST_REAPER_CHILD"

// TestHoldReaper_KeepsAContainerWithNoClientOfItsOwn: a session container whose
// own Ryuk connection is gone, as in the failed CI run, survives a gap with no
// other client once the binary holds the reaper. Without the hold Ryuk reaps it.
func TestHoldReaper_KeepsAContainerWithNoClientOfItsOwn(t *testing.T) {
	if testcontainers.ReadConfig().Config.RyukDisabled {
		t.Skip("ryuk disabled")
	}
	for _, tc := range []struct {
		mode  string
		alive bool
	}{{"hold", true}, {"none", false}} {
		t.Run(tc.mode, func(t *testing.T) {
			t.Parallel()
			// The session id hashes the parent pid, so a shell in between gives each
			// child its own session and a Ryuk that sees only that child's clients.
			cmd := exec.Command("sh", "-c", `"$0" "$@"; exit $?`, os.Args[0], "-test.run=^TestReaperChild$", "-test.count=1")
			cmd.Env = append(os.Environ(), childMode+"="+tc.mode, "TESTCONTAINERS_RYUK_RECONNECTION_TIMEOUT=2s")
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child: %v\n%s", err, out)
			}
			if !strings.Contains(string(out), "orphan: ") {
				t.Fatalf("child printed no orphan state\n%s", out)
			}
			if got := strings.Contains(string(out), "orphan: alive"); got != tc.alive {
				t.Fatalf("orphan alive = %v, want %v\n%s", got, tc.alive, out)
			}
		})
	}
}

// TestReaperChild runs only as the child of the test above.
func TestReaperChild(t *testing.T) {
	mode := os.Getenv(childMode)
	if mode == "" {
		t.Skip("child of TestHoldReaper_KeepsAContainerWithNoClientOfItsOwn")
	}
	ctx := context.Background()
	lib, err := testcontainers.Run(ctx, Image, testcontainers.WithEntrypoint("sleep", "120"))
	if err != nil {
		t.Fatalf("library container: %v", err)
	}

	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	orphan, err := cli.ContainerCreate(ctx, client.ContainerCreateOptions{Config: &container.Config{
		Image: Image, Entrypoint: []string{"sleep", "120"}, Labels: testcontainers.GenericLabels(),
	}})
	if err != nil {
		t.Fatalf("orphan create: %v", err)
	}
	defer func() { _, _ = cli.ContainerRemove(ctx, orphan.ID, client.ContainerRemoveOptions{Force: true}) }()
	if _, err := cli.ContainerStart(ctx, orphan.ID, client.ContainerStartOptions{}); err != nil {
		t.Fatalf("orphan start: %v", err)
	}

	if mode == "hold" {
		if err := holdReaper(ctx, lib); err != nil {
			t.Fatal(err)
		}
	}
	// The library's only client goes, then Ryuk waits out its 2 s reconnection timeout.
	if err := lib.Terminate(ctx, testcontainers.StopTimeout(0)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(6 * time.Second)

	res, err := cli.ContainerInspect(ctx, orphan.ID, client.ContainerInspectOptions{})
	state := "gone"
	if err == nil && res.Container.State.Running {
		state = "alive"
	}
	fmt.Println("orphan: " + state)
}

// TestStartPostgres_HoldsTheReaper: a started database leaves the binary holding
// its own Ryuk connection, so the shared container never rests on the library's.
func TestStartPostgres_HoldsTheReaper(t *testing.T) {
	if testcontainers.ReadConfig().Config.RyukDisabled {
		t.Skip("ryuk disabled")
	}
	StartPostgres(t)
	held.mu.Lock()
	defer held.mu.Unlock()
	if held.conn == nil {
		t.Fatal("no reaper connection held after StartPostgres")
	}
}
