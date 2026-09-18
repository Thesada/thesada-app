package mqtt

import "testing"

// topicMatches reports whether an MQTT topic matches a subscription filter.
// Only the wildcards this package actually uses are modelled: '#' as a
// trailing multi-level wildcard, '+' as a single level.
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

// The whole point of the split: a device subscribed to the input wildcard must
// not receive its own responses. On cellular that echo arrives as a URC too
// large for the modem line buffer, which is the bug this effort removes.
func TestCLIResponseTopicDoesNotMatchInputSubscription(t *testing.T) {
	const prefix = "thesada/acme/owb"
	sub := CLIInputSubscription(prefix)

	if topicMatches(sub, CLIResponseTopic(prefix)) {
		t.Errorf("response topic %q matches input subscription %q - the echo is back",
			CLIResponseTopic(prefix), sub)
	}
	// The pre-split topic did match, which is why it had to move. Kept as a
	// literal so this test still proves the wildcard would catch a response
	// that lives under cli/.
	if !topicMatches(sub, prefix+"/cli/response") {
		t.Errorf("a cli/-prefixed response unexpectedly does not match %q - test no longer proves anything", sub)
	}
}

func TestCLITopicConstruction(t *testing.T) {
	const prefix = "thesada/acme/owb"
	cases := []struct{ got, want string }{
		{CLICommandTopic(prefix, "fs.cat"), "thesada/acme/owb/cli/fs.cat"},
		{CLIInputSubscription(prefix), "thesada/acme/owb/cli/#"},
		{CLIResponseTopic(prefix), "thesada/acme/owb/cli_response"},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

// A command topic must stay inside the input wildcard, or commands stop
// arriving - the failure mode opposite to the echo.
func TestCLICommandTopicMatchesInputSubscription(t *testing.T) {
	const prefix = "thesada/acme/owb"
	sub := CLIInputSubscription(prefix)
	for _, cmd := range []string{"fs.cat", "restart", "ota.check", "config.dump"} {
		if !topicMatches(sub, CLICommandTopic(prefix, cmd)) {
			t.Errorf("command %q does not match input subscription %q", cmd, sub)
		}
	}
}
