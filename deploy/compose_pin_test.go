package deploy

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
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
	// The release workflow sets it to the tag it ships, and that tag must be the pin.
	rel := os.Getenv("THESADA_RELEASE_TAG")
	if err := releasePinErr(tag, rel, os.Getenv("GITHUB_REF_TYPE")); err != nil {
		t.Fatal(err)
	}
	if rel != "" {
		if err := releaseNotesErr(releaseNotesPath(rel)); err != nil {
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

// A release ships exactly the version its compose file pins.
func TestReleasePinErr(t *testing.T) {
	for _, tc := range []struct {
		pin, rel, refType string
		ok                bool
	}{
		{"26.11.5", "26.11.5", "tag", true},
		{"26.11.5", "26.11.6", "tag", false},
		{"26.11.6", "26.11.5", "tag", false},
		{"26.11.4", "26.11.5", "tag", false},
		{"26.11.5", "v26.11.5", "tag", false},
		{"26.11.5", "26.11.5-rc.1", "tag", false},
		{"26.11.5", "", "tag", false},
		{"26.11.5", "", "branch", true},
		{"26.11.5", "", "", true},
	} {
		if err := releasePinErr(tc.pin, tc.rel, tc.refType); (err == nil) != tc.ok {
			t.Errorf("releasePinErr(%q, %q, %q) = %v, want ok=%v", tc.pin, tc.rel, tc.refType, err, tc.ok)
		}
	}
}

// The image tag and the binary version come from the same tag the pin job checks.
func TestReleaseShipsTheCheckedTag(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	jobs := workflowJobs(string(raw))
	for _, want := range []string{"type=ref,event=tag", "VERSION=${{ github.ref_name }}"} {
		if !strings.Contains(jobs["image"], want) {
			t.Errorf("image job lacks %q:\n%s", want, jobs["image"])
		}
	}
	if !strings.Contains(jobs["binary"], "VERSION: ${{ github.ref_name }}") {
		t.Errorf("binary job does not build VERSION from the tag:\n%s", jobs["binary"])
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
	for _, name := range []string{"image", "binary", "notes"} {
		if !slices.Contains(jobNeeds(jobs[name]), "pin") {
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

// releasePinErr checks the pin against the tag being cut. in: pin, tag, GITHUB_REF_TYPE. out: error.
func releasePinErr(pin, rel, refType string) error {
	if rel == "" {
		if refType == "tag" {
			return errors.New("a tag build must set THESADA_RELEASE_TAG to the tag it releases")
		}
		return nil
	}
	if err := releaseTagErr(rel); err != nil {
		return err
	}
	if pin != rel {
		return fmt.Errorf("compose pins %s, the release tag is %s: run make release-pin RELEASE=%s", pin, rel, rel)
	}
	return nil
}

// releaseNotesPath is the notes file a release body starts with. in: tag. out: path from deploy/.
func releaseNotesPath(tag string) string {
	return filepath.Join("..", "docs", "release-notes", tag+".md")
}

// releaseNotesErr refuses a release without its notes file. in: path. out: error.
func releaseNotesErr(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("release notes %s: %w, the release PR adds it", path, err)
	}
	if strings.TrimSpace(string(raw)) == "" {
		return fmt.Errorf("release notes %s are empty", path)
	}
	return nil
}

func TestReleaseNotesErr(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, tc := range []struct {
		path string
		ok   bool
	}{
		{filepath.Join(dir, "missing.md"), false},
		{write("empty.md", ""), false},
		{write("blank.md", " \n\t\n"), false},
		{write("notes.md", "- a line\n"), true},
	} {
		if err := releaseNotesErr(tc.path); (err == nil) != tc.ok {
			t.Errorf("releaseNotesErr(%s) = %v, want ok=%v", filepath.Base(tc.path), err, tc.ok)
		}
	}
}

// The release the compose file pins has its notes, so the release PR cannot leave them out.
func TestReleaseNotesForThePin(t *testing.T) {
	raw, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	pin, err := composeAppPin(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if err := releaseNotesErr(releaseNotesPath(pin)); err != nil {
		t.Fatal(err)
	}
}

// The notes job creates the release with the notes file ahead of the generated notes,
// and the upload jobs after it leave the body alone.
func TestReleaseBodyCarriesTheNotes(t *testing.T) {
	raw, err := os.ReadFile("../.github/workflows/release.yml")
	if err != nil {
		t.Fatal(err)
	}
	jobs := workflowJobs(string(raw))
	for _, want := range []string{"body_path: docs/release-notes/${{ github.ref_name }}.md", "generate_release_notes: true"} {
		if !strings.Contains(jobs["notes"], want) {
			t.Errorf("notes job lacks %q:\n%s", want, jobs["notes"])
		}
	}
	if !slices.Contains(jobNeeds(jobs["binary"]), "notes") {
		t.Errorf("binary job uploads before the notes job made the release:\n%s", jobs["binary"])
	}
	for _, bad := range []string{"generate_release_notes", "body"} {
		if strings.Contains(jobs["binary"], bad) {
			t.Errorf("binary job sets %s, which rewrites the release body:\n%s", bad, jobs["binary"])
		}
	}
}

// jobNeeds reads a job's needs line, one name or a [list]. in: job body. out: job names.
func jobNeeds(job string) []string {
	for line := range strings.SplitSeq(job, "\n") {
		v, ok := strings.CutPrefix(line, "    needs: ")
		if !ok {
			continue
		}
		out := strings.Split(strings.Trim(v, "[] "), ",")
		for i, n := range out {
			out[i] = strings.TrimSpace(n)
		}
		return out
	}
	return nil
}
