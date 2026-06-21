// Cheap unit tests for the pure-function parsers in pkg/mqtt. These do not
// touch the broker or the DB - they exist to guard the parser shape against
// regressions while we add proper integration coverage later.
package mqtt

import (
	"errors"
	"strings"
	"testing"
)

func TestParseSensorPayload(t *testing.T) {
	cases := []struct {
		name     string
		payload  string
		wantNum  *float64
		wantText string
		wantOK   bool
	}{
		{"bare int", "42", floatp(42), "", true},
		{"bare float", "3.14", floatp(3.14), "", true},
		{"bare negative", "-12.5", floatp(-12.5), "", true},
		{"bare json string", `"Discharging"`, nil, "Discharging", true},
		{"object with value", `{"value":42.0,"text":"foo"}`, floatp(42), "foo", true},
		{"object with text only", `{"text":"On"}`, nil, "On", true},
		{"object with value only", `{"value":7}`, floatp(7), "", true},
		{"unquoted legacy text", "Discharging", nil, "Discharging", true},
		{"unquoted On", "On", nil, "On", true},
		{"empty", "", nil, "", false},
		{"whitespace only", "   ", nil, "", false},
		{"mixed - just whitespace+text", " yes ", nil, "yes", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotNum, gotText, gotOK := parseSensorPayload([]byte(tc.payload))
			if gotOK != tc.wantOK {
				t.Fatalf("ok mismatch: got %v want %v (payload=%q)", gotOK, tc.wantOK, tc.payload)
			}
			if !floatEq(gotNum, tc.wantNum) {
				t.Fatalf("num mismatch: got %v want %v (payload=%q)", deref(gotNum), deref(tc.wantNum), tc.payload)
			}
			if gotText != tc.wantText {
				t.Fatalf("text mismatch: got %q want %q (payload=%q)", gotText, tc.wantText, tc.payload)
			}
		})
	}
}

func TestCompileMQTTMatcher(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		topic   string
		want    bool
		err     bool
	}{
		{"exact match", "thesada/cyd/cli/response", "thesada/cyd/cli/response", true, false},
		{"single-level + match", "thesada/+/info", "thesada/owb/info", true, false},
		{"single-level + no match across levels", "thesada/+/info", "thesada/owb/extra/info", false, false},
		{"trailing # match", "thesada/cyd/#", "thesada/cyd/sensor/temp", true, false},
		{"trailing # match zero levels", "thesada/cyd/#", "thesada/cyd", true, false}, // MQTT spec: # matches zero or more trailing levels
		{"trailing # match exact", "thesada/cyd/#", "thesada/cyd/", true, false},
		{"# in middle is invalid", "thesada/#/info", "", false, true},
		{"empty pattern", "", "", false, true},
		{"more topic parts than pattern", "thesada/cyd", "thesada/cyd/extra", false, false},
		{"more pattern parts than topic", "thesada/cyd/extra", "thesada/cyd", false, false},
		{"+ at root", "+", "thesada", true, false},
		{"+ then # together", "+/cli/#", "thesada/cli/response", true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := compileMQTTMatcher(tc.pattern)
			if tc.err {
				if err == nil {
					t.Fatalf("expected error for pattern %q, got nil", tc.pattern)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for pattern %q: %v", tc.pattern, err)
			}
			got := matcher(tc.topic)
			if got != tc.want {
				t.Fatalf("matcher(%q)(%q) = %v, want %v", tc.pattern, tc.topic, got, tc.want)
			}
		})
	}
}

// TestCompileMQTTMatcherValidation covers the MQTT 3.1.1 section 4.7 filter
// validation rules. Each sub-test targets one specific
// constraint (or confirms a valid filter still compiles). Error-path cases only
// check that an error is returned and that it wraps ErrTapPattern - the exact
// message text is intentionally NOT asserted so the messages can be tuned
// without breaking the test suite.
func TestCompileMQTTMatcherValidation(t *testing.T) {
	type tc struct {
		name       string
		pattern    string
		wantErr    bool
		errContain string // substring that must appear in the error message when wantErr=true
		// When wantErr=false: topic/wantMatch are used to exercise the matcher.
		topic     string
		wantMatch bool
	}

	cases := []tc{
		// --- valid filters --------------------------------------------------
		{
			name: "hash alone is valid",
			pattern: "#", topic: "thesada/default/sht31/status", wantMatch: true,
		},
		{
			name: "hash after slash is valid",
			pattern: "thesada/#", topic: "thesada/acme/owb/sensor/temp", wantMatch: true,
		},
		{
			name: "plus alone is valid",
			pattern: "+", topic: "thesada", wantMatch: true,
		},
		{
			name: "plus at first level is valid",
			pattern: "+/status", topic: "sht31/status", wantMatch: true,
		},
		{
			name: "multiple plus levels is valid",
			pattern: "thesada/+/+/status", topic: "thesada/acme/owb/status", wantMatch: true,
		},
		{
			name: "plus and hash combined is valid",
			pattern: "thesada/+/+/#", topic: "thesada/acme/owb/sensor/temp", wantMatch: true,
		},
		{
			name: "leading slash is valid (empty first level)",
			pattern: "/status", topic: "/status", wantMatch: true,
		},
		{
			name: "exact multi-level no wildcards is valid",
			pattern: "thesada/default/sht31/sensor/temp", topic: "thesada/default/sht31/sensor/temp", wantMatch: true,
		},

		// --- invalid: + mixed with literal characters ----------------------
		{
			name:       "plus prefix in segment is invalid",
			pattern:    "thesada/+foo/bar",
			wantErr:    true,
			errContain: "'+' must occupy an entire level",
		},
		{
			name:       "plus suffix in segment is invalid",
			pattern:    "thesada/foo+/bar",
			wantErr:    true,
			errContain: "'+' must occupy an entire level",
		},
		{
			name:       "plus embedded in segment is invalid",
			pattern:    "thesada/f+o/bar",
			wantErr:    true,
			errContain: "'+' must occupy an entire level",
		},
		{
			name:       "plus at root mixed with literal is invalid",
			pattern:    "+thesada",
			wantErr:    true,
			errContain: "'+' must occupy an entire level",
		},
		{
			name:       "plus as trailing chars in last segment is invalid",
			pattern:    "thesada/status+",
			wantErr:    true,
			errContain: "'+' must occupy an entire level",
		},

		// --- invalid: # not the last character / not its own level ---------
		{
			name:       "hash mid-filter not last level is invalid",
			pattern:    "thesada/#/status",
			wantErr:    true,
			errContain: "'#' at level",
		},
		{
			name:       "hash at first level not last is invalid",
			pattern:    "#/status",
			wantErr:    true,
			errContain: "'#' at level",
		},
		{
			name:       "hash mixed with literal prefix is invalid",
			pattern:    "thesada/foo#",
			wantErr:    true,
			errContain: "'#' must occupy an entire level",
		},
		{
			name:       "hash mixed with literal suffix is invalid",
			pattern:    "thesada/#bar",
			wantErr:    true,
			errContain: "'#' must occupy an entire level",
		},
		{
			name:       "hash embedded in segment is invalid",
			pattern:    "thesada/f#o/bar",
			wantErr:    true,
			errContain: "'#' must occupy an entire level",
		},

		// --- invalid: consecutive slashes producing empty non-leading segments
		{
			name:       "consecutive slashes mid-filter is invalid",
			pattern:    "thesada//status",
			wantErr:    true,
			errContain: "empty segment",
		},
		{
			name:       "trailing slash is invalid",
			pattern:    "thesada/status/",
			wantErr:    true,
			errContain: "empty segment",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			matcher, err := compileMQTTMatcher(tc.pattern)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("pattern %q: expected error containing %q, got nil", tc.pattern, tc.errContain)
				}
				if !errors.Is(err, ErrTapPattern) {
					t.Fatalf("pattern %q: error %v does not wrap ErrTapPattern", tc.pattern, err)
				}
				if tc.errContain != "" && !strings.Contains(err.Error(), tc.errContain) {
					t.Fatalf("pattern %q: error %q does not contain expected substring %q", tc.pattern, err.Error(), tc.errContain)
				}
				return
			}
			if err != nil {
				t.Fatalf("pattern %q: unexpected error: %v", tc.pattern, err)
			}
			got := matcher(tc.topic)
			if got != tc.wantMatch {
				t.Fatalf("pattern %q against topic %q: got %v, want %v", tc.pattern, tc.topic, got, tc.wantMatch)
			}
		})
	}
}

func floatp(v float64) *float64 { return &v }
func floatEq(a, b *float64) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	return *a == *b
}
func deref(p *float64) interface{} {
	if p == nil {
		return nil
	}
	return *p
}
