// Runs startup.sh against a stub docker that logs its calls, so the order of
// the bootstrap steps is checked without a daemon.
package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestStartupUpdatesExtensionBeforeMigrations(t *testing.T) {
	dir := t.TempDir()
	for _, f := range []string{"startup.sh", "app.env.example", "db.env.example"} {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, f), raw, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(dir, "docker.log")
	stub := "#!/bin/sh\necho \"$*\" >> " + log + "\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", filepath.Join(dir, "startup.sh"))
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("startup.sh: %v\n%s", err, out)
	}
	raw, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	calls := string(raw)
	update := strings.Index(calls, "ALTER EXTENSION timescaledb UPDATE")
	migrate := strings.Index(calls, "run --rm app migrate")
	if update < 0 || migrate < 0 || update > migrate {
		t.Fatalf("want ALTER EXTENSION timescaledb UPDATE before the migrations, docker calls:\n%s", calls)
	}
	if !strings.Contains(calls[:update], "up -d --wait timescaledb") {
		t.Fatalf("extension update runs before the database is healthy, docker calls:\n%s", calls)
	}
}
