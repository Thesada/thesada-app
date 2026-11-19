package deploy

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

var (
	composePinRE = regexp.MustCompile(`(?m)^\s*image:\s*ghcr\.io/thesada/thesada-app:(\S+)\s*$`)
	calVerRE     = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)$`)
	// The make release-pin shape: a release tag is YY.MM.N, nothing else ships.
	releaseTagRE = regexp.MustCompile(`^[0-9]{2}\.[0-9]{1,2}\.[0-9]+$`)
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
	// The release workflow sets it to the tag it ships.
	if rel := os.Getenv("THESADA_RELEASE_TAG"); rel != "" {
		if err := releaseTagErr(rel); err != nil {
			t.Fatal(err)
		}
	}
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

// The release workflow fires only on CalVer-shaped tags, and its pin job hands the tag to the pin check.
func TestReleaseTriggerIsCalVerOnly(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	pats := releaseTagGlobs(string(raw))
	if len(pats) == 0 {
		t.Fatal("release.yml lists no tag trigger")
	}
	for _, p := range pats {
		if !strings.HasPrefix(p, "[0-9][0-9].") {
			t.Errorf("release.yml fires on tag pattern %q, want CalVer YY.MM.N patterns only", p)
		}
	}
	if pin := workflowJobs(string(raw))["pin"]; !strings.Contains(pin, "THESADA_RELEASE_TAG: ${{ github.ref_name }}") {
		t.Errorf("pin job does not pass the tag to the pin check:\n%s", pin)
	}
}

func TestReleaseTagErr(t *testing.T) {
	for _, tc := range []struct {
		tag string
		ok  bool
	}{
		{"26.11.5", true},
		{"26.6.1", true},
		{"v26.11.5", false},
		{"v1.2.3", false},
		{"1.2.3", false},
		{"26.11.5-rc.1", false},
		{"", false},
	} {
		if err := releaseTagErr(tc.tag); (err == nil) != tc.ok {
			t.Errorf("releaseTagErr(%q) = %v, want ok=%v", tc.tag, err, tc.ok)
		}
	}
}

// releaseTagErr refuses a release tag that is not CalVer YY.MM.N. in: tag. out: error.
func releaseTagErr(tag string) error {
	if !releaseTagRE.MatchString(tag) {
		return fmt.Errorf("release tag %q is not CalVer YY.MM.N, releases are CalVer only", tag)
	}
	return nil
}

// releaseTagGlobs returns the push tag filters of a workflow. in: workflow. out: patterns.
func releaseTagGlobs(raw string) []string {
	_, rest, ok := strings.Cut(raw, "\n    tags:\n")
	if !ok {
		return nil
	}
	var out []string
	for line := range strings.SplitSeq(rest, "\n") {
		item, ok := strings.CutPrefix(line, "      - ")
		if !ok {
			break
		}
		item, _, _ = strings.Cut(item, "#")
		out = append(out, strings.Trim(strings.TrimSpace(item), `"'`))
	}
	return out
}

// A tag pushed after the last CI run is checked by the release itself, before anything ships.
func TestReleaseJobsWaitForThePinCheck(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	jobs := workflowJobs(string(raw))
	pin, ok := jobs["pin"]
	if !ok {
		t.Fatalf("release.yml has no pin job, jobs: %v", slices.Sorted(maps.Keys(jobs)))
	}
	for _, want := range []string{"fetch-depth: 0", `THESADA_REQUIRE_TAGS: "1"`, "make pin-check"} {
		if !strings.Contains(pin, want) {
			t.Errorf("pin job lacks %q:\n%s", want, pin)
		}
	}
	for _, name := range []string{"image", "binary"} {
		if !strings.Contains("\n"+jobs[name], "\n    needs: pin\n") {
			t.Errorf("release job %s does not need pin:\n%s", name, jobs[name])
		}
	}
	mk, err := os.ReadFile("../Makefile")
	if err != nil {
		t.Fatal(err)
	}
	_, recipe, _ := strings.Cut(string(mk), "\npin-check:")
	recipe, _, _ = strings.Cut(recipe, "\n\n")
	if !strings.Contains(recipe, "-count=1") || !strings.Contains(recipe, "TestComposePinIsNotBehindNewestTag") {
		t.Errorf("make pin-check recipe %q does not run the pin test uncached", recipe)
	}
}

// workflowJobs splits a workflow's jobs block by job name. in: workflow. out: name to body.
func workflowJobs(raw string) map[string]string {
	jobs := map[string]string{}
	_, body, _ := strings.Cut(raw, "\njobs:\n")
	name := ""
	for line := range strings.SplitSeq(body, "\n") {
		if len(line) > 2 && line[:2] == "  " && line[2] != ' ' && strings.HasSuffix(line, ":") {
			name = strings.TrimSuffix(line[2:], ":")
			continue
		}
		if name != "" {
			jobs[name] += line + "\n"
		}
	}
	return jobs
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
