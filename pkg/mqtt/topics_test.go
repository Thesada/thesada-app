package mqtt

import "testing"

// topicMatches reports whether an MQTT topic matches a subscription filter.
// Only the wildcards this package uses are modelled: '#' trailing multi-level,
// '+' single level.
func topicMatches(filter, topic string) bool {
	fp := splitTopic(filter)
	tp := splitTopic(topic)
	for i, f := range fp {
		if f == "#" {
			return true
		}
		if i >= len(tp) {
			return false
		}
		if f != "+" && f != tp[i] {
			return false
		}
	}
	return len(fp) == len(tp)
}

func splitTopic(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func TestCLITopicConstruction(t *testing.T) {
	const prefix = "thesada/acme/owb"
	cases := []struct{ got, want string }{
		{CLICommandTopic(prefix, "fs.cat"), "thesada/acme/owb/cli/fs.cat"},
		{CLIInputSubscription(prefix), "thesada/acme/owb/cli/#"},
		{CLIResponseTopic(prefix), "thesada/acme/owb/cli/response"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

// A command topic must sit inside the input wildcard, or commands stop
// arriving at the device.
func TestCLICommandTopicMatchesInputSubscription(t *testing.T) {
	const prefix = "thesada/acme/owb"
	sub := CLIInputSubscription(prefix)
	for _, cmd := range []string{"fs.cat", "restart", "ota.check", "config.dump"} {
		if !topicMatches(sub, CLICommandTopic(prefix, cmd)) {
			t.Errorf("command %q does not match input subscription %q", cmd, sub)
		}
	}
}

// Documents the bug this migration is groundwork for: the response topic sits
// inside the device's own command subscription, so every response echoes back
// to the device that just sent it.
func TestCLIResponseTopicCurrentlyMatchesInputSubscription(t *testing.T) {
	const prefix = "thesada/acme/owb"
	if !topicMatches(CLIInputSubscription(prefix), CLIResponseTopic(prefix)) {
		t.Error("response topic no longer matches the input subscription - update this test")
	}
}

func TestTopicMatcherSanity(t *testing.T) {
	cases := []struct {
		filter, topic string
		want          bool
	}{
		{"a/b/#", "a/b/c", true},
		{"a/b/#", "a/b/c/d", true},
		{"a/+/c", "a/b/c", true},
		{"a/+/c", "a/b/d", false},
		{"a/b/c", "a/b", false},
		{"a/b/c", "a/b/c", true},
		{"a/b", "a/b/c", false},
	}
	for _, c := range cases {
		if got := topicMatches(c.filter, c.topic); got != c.want {
			t.Errorf("topicMatches(%q, %q) = %v, want %v", c.filter, c.topic, got, c.want)
		}
	}
}
