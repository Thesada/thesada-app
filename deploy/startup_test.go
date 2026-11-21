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
	calls, out, err := runStartup(t, dir, "2.29.1")
	if err != nil {
		t.Fatalf("startup.sh: %v\n%s", err, out)
	}
	update := strings.Index(calls, "ALTER EXTENSION timescaledb UPDATE")
	migrate := strings.Index(calls, "run --rm app migrate")
	if update < 0 || migrate < 0 || update > migrate {
		t.Fatalf("want ALTER EXTENSION timescaledb UPDATE before the migrations, docker calls:\n%s", calls)
	}
	if !strings.Contains(calls[:update], "up -d --wait timescaledb") {
		t.Fatalf("extension update runs before the database is healthy, docker calls:\n%s", calls)
	}
	if create := strings.Index(calls, "CREATE EXTENSION IF NOT EXISTS timescaledb"); create < 0 || create > update {
		t.Fatalf("want CREATE EXTENSION IF NOT EXISTS before the update, docker calls:\n%s", calls)
	}
}

func TestStartupRefusesOldCompose(t *testing.T) {
	for _, v := range []string{"2.16.0", "v2.3.3", "1.29.2", ""} {
		calls, out, err := runStartup(t, t.TempDir(), v)
		if err == nil || !strings.Contains(out, "2.17 or newer") {
			t.Errorf("compose %q: err=%v out=%s, want a refusal", v, err, out)
		}
		if strings.Contains(calls, "pull") {
			t.Errorf("compose %q: startup.sh went on to pull", v)
		}
	}
	for _, v := range []string{"2.17.0", "v2.29.1", "2.40.3", "3.0.0"} {
		if _, out, err := runStartup(t, t.TempDir(), v); err != nil {
			t.Errorf("compose %q refused: %v\n%s", v, err, out)
		}
	}
}

// runStartup runs startup.sh in dir against a stub docker reporting composeVersion.
// out: the logged docker calls, the script output, its error.
func runStartup(t *testing.T, dir, composeVersion string) (string, string, error) {
	t.Helper()
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
	stub := "#!/bin/sh\necho \"$*\" >> " + log + "\n" +
		"[ \"$*\" = \"compose version --short\" ] && echo '" + composeVersion + "'\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(stub), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", filepath.Join(dir, "startup.sh"))
	cmd.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"))
	out, err := cmd.CombinedOutput()
	raw, _ := os.ReadFile(log)
	return string(raw), string(out), err
}
