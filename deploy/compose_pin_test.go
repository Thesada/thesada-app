package deploy

import (
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var (
	composePinRE = regexp.MustCompile(`ghcr\.io/thesada/thesada-app:([0-9]+\.[0-9]+\.[0-9]+)`)
	calVerRE     = regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)$`)
)

// A release tag must ship a compose file that runs that release, not the one before.
func TestComposePinIsNotBehindNewestTag(t *testing.T) {
	raw, err := os.ReadFile("docker-compose.yml")
	if err != nil {
		t.Fatal(err)
	}
	m := composePinRE.FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("docker-compose.yml has no thesada-app image pin")
	}
	pin, ok := calVer(m[1])
	if !ok {
		t.Fatalf("pin %q is not YY.MM.N", m[1])
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
		t.Fatalf("compose pins %s, the newest tag is %s: run make release-pin RELEASE=<version>", m[1], name)
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
