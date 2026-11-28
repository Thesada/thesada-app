//go:build integration

package servicetest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"testing"

	"github.com/moby/moby/client"
	"github.com/testcontainers/testcontainers-go"
)

// TestStart_Smoke validates the harness end to end: a container comes up, every
// migration applies, all three role pools connect, and a Services bundle is
// wired. The ingest role is on Env.MQTTRole, not Pools, since nothing routes
// through it. If this passes, per-service integration tests can rely on Start.
func TestStart_Smoke(t *testing.T) {
	env := Start(t)
	ctx := context.Background()

	for name, pool := range map[string]interface{ Ping(context.Context) error }{
		"app":   env.Pools.App,
		"admin": env.Pools.Admin,
		"mqtt":  env.MQTTRole,
		"super": env.Super,
	} {
		if err := pool.Ping(ctx); err != nil {
			t.Errorf("ping %s pool: %v", name, err)
		}
	}

	if env.Services == nil || env.Services.Devices == nil || env.Services.Auth == nil {
		t.Fatal("Services bundle not wired")
	}

	// Seed + read-back through the superuser pool proves migrations built the
	// schema and the fixture helper works.
	env.SeedTenant(t, "smoke-tenant")
	var n int
	if err := env.Super.QueryRow(ctx,
		`SELECT count(*) FROM tenants WHERE id = $1`, "smoke-tenant").Scan(&n); err != nil {
		t.Fatalf("read back seeded tenant: %v", err)
	}
	if n != 1 {
		t.Errorf("seeded tenant count = %d, want 1", n)
	}
}

// TestStart_FreshDatabaseEachCall: Start clones the migrated template, so rows
// from an earlier Start are gone, while the owner and the database ACL
// (migration 0001 grants CONNECT) carry over to the clone.
func TestStart_FreshDatabaseEachCall(t *testing.T) {
	ctx := context.Background()
	Start(t).SeedTenant(t, "first-start")

	env := Start(t)
	var n int
	if err := env.Super.QueryRow(ctx, `SELECT count(*) FROM tenants WHERE id = $1`, "first-start").Scan(&n); err != nil {
		t.Fatalf("count tenants: %v", err)
	}
	if n != 0 {
		t.Errorf("first Start's tenant after a second Start = %d rows, want 0", n)
	}

	var owner string
	if err := env.Super.QueryRow(ctx,
		`SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname = current_database()`).Scan(&owner); err != nil {
		t.Fatalf("read owner: %v", err)
	}
	if owner != "thesada_app" {
		t.Errorf("database owner = %q, want thesada_app", owner)
	}
	var acl, tmplACL *string
	if err := env.Super.QueryRow(ctx, `
		SELECT (SELECT datacl::text FROM pg_database WHERE datname = current_database()),
		       (SELECT datacl::text FROM pg_database WHERE datname = $1)`, tmplName).Scan(&acl, &tmplACL); err != nil {
		t.Fatalf("read database ACLs: %v", err)
	}
	if tmplACL == nil || acl == nil || *acl != *tmplACL {
		t.Errorf("database ACL = %s, want the template's %s", show(acl), show(tmplACL))
	}
}

// show prints a nullable text column.
func show(s *string) string {
	if s == nil {
		return "NULL"
	}
	return *s
}

// startChild makes this binary the Start child of the test below.
const startChild = "SERVICETEST_START_CHILD"

// TestStart_RyukDisabledLeavesNoContainer: without Ryuk nothing reaps a shared
// container, so a test binary that ran Start leaves no container of its session.
func TestStart_RyukDisabledLeavesNoContainer(t *testing.T) {
	// A shell in between gives the child its own session id.
	cmd := exec.Command("sh", "-c", `"$0" "$@"; exit $?`, os.Args[0], "-test.run=^TestStartChild$", "-test.count=1")
	cmd.Env = append(os.Environ(), startChild+"=1", "TESTCONTAINERS_RYUK_DISABLED=true")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	m := regexp.MustCompile(`(?m)^ryuk disabled=true, session: (\S+)$`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("child printed no session with ryuk disabled\n%s", out)
	}
	ctx := context.Background()
	cli, err := testcontainers.NewDockerClientWithOpts(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cli.Close() }()
	list, err := cli.ContainerList(ctx, client.ContainerListOptions{All: true,
		Filters: make(client.Filters).Add("label", "org.testcontainers.sessionId="+string(m[1]))})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range list.Items {
		_, _ = cli.ContainerRemove(ctx, c.ID, client.ContainerRemoveOptions{Force: true})
	}
	if len(list.Items) != 0 {
		t.Fatalf("%d containers of the child's session left after it exited", len(list.Items))
	}
}

// TestStartChild runs only as the child of the test above.
func TestStartChild(t *testing.T) {
	if os.Getenv(startChild) == "" {
		t.Skip("child of TestStart_RyukDisabledLeavesNoContainer")
	}
	Start(t)
	fmt.Printf("ryuk disabled=%v, session: %s\n", testcontainers.ReadConfig().Config.RyukDisabled, testcontainers.SessionID())
}
