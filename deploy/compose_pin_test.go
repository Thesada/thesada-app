package deploy

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	composePinRE = regexp.MustCompile(`(?m)^\s*image:\s*ghcr\.io/thesada/thesada-app:(\S+)\s*$`)
	calVerRE     = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)$`)
)

// A release tag must ship a compose file that runs that release, not the one before.
func TestComposePinIsNotBehindNewestTag(t *testing.T) {
	raw, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	tag, err := composeAppPin(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	pin, _ := calVer(tag)
	// CI sets it, so a checkout without tags cannot pass the pin unchecked.
	skip := t.Skipf
	if os.Getenv("THESADA_REQUIRE_TAGS") != "" {
		skip = t.Fatalf
	}
	out, err := exec.Command("git", "tag", "--list").Output()
	if err != nil {
		skip("no git tags here: %v", err)
	}
	var newest [3]int
	name := ""
	for _, tag := range strings.Fields(string(out)) {
		if v, ok := calVer(tag); ok && less(newest, v) {
			newest, name = v, tag
		}
	}
	if name == "" {
		skip("no release tags in this checkout")
	}
	if less(pin, newest) {
		t.Fatalf("compose pins %s, the newest tag is %s: run make release-pin RELEASE=<version>", tag, name)
	}
}

// composeAppPin returns the thesada-app image tag compose runs. in: compose file. out: tag, error.
func composeAppPin(raw string) (string, error) {
	m := composePinRE.FindStringSubmatch(raw)
	if m == nil {
		return "", errors.New("docker-compose.yml has no thesada-app image pin")
	}
	if _, ok := calVer(m[1]); !ok {
		return "", fmt.Errorf("pin %q is not YY.MM.N", m[1])
	}
	return m[1], nil
}

func TestComposeAppPin(t *testing.T) {
	for _, tc := range []struct {
		raw, want string
		ok        bool
	}{
		{"    image: ghcr.io/thesada/thesada-app:26.11.5\n", "26.11.5", true},
		{"    image: ghcr.io/thesada/thesada-app:26.11.5-rc.1\n", "", false},
		{"    image: ghcr.io/thesada/thesada-app:26.11.5@sha256:00\n", "", false},
		{"    image: ghcr.io/thesada/thesada-app:latest\n", "", false},
		{"    image: timescale/timescaledb:2.31.0-pg17\n", "", false},
	} {
		got, err := composeAppPin(tc.raw)
		if (err == nil) != tc.ok || got != tc.want {
			t.Errorf("composeAppPin(%q) = %q, %v, want %q ok=%v", tc.raw, got, err, tc.want, tc.ok)
		}
	}
}

// go test does not see git tags as an input, so make test must run this package uncached.
func TestMakeTestRunsDeployUncached(t *testing.T) {
	raw, err := os.ReadFile("../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	_, recipe, _ := strings.Cut(string(raw), "\ntest:")
	recipe, _, _ = strings.Cut(recipe, "\n\n")
	if !strings.Contains(recipe, "-count=1 ./deploy/") {
		t.Errorf("make test recipe %q does not run ./deploy/ with -count=1", recipe)
	}
}

func calVer(s string) ([3]int, bool) {
	m := calVerRE.FindStringSubmatch(s)
	if m == nil {
		return [3]int{}, false
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	return v, true
}

func less(a, b [3]int) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
