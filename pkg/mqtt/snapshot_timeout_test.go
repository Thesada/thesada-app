package mqtt

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

// A drift pull waits CLIRequestTimeout per round trip, not a fixed 10 or 15 s,
// so a slow cellular link gets the operator's budget and a dead device frees
// the CLI lock when that budget ends.
func TestDriftPull_UsesConfiguredCLITimeout(t *testing.T) {
	silent := &answerBroker{} // the device never answers
	for name, pull := range map[string]func(c *Client){
		"config.json": func(c *Client) {
			c.pullAndSnapshot("t", uuid.New(), "thesada/t/d", "config.json", "drift", "")
		},
		"script chunk": func(c *Client) {
			c.pullAndSnapshot("t", uuid.New(), "thesada/t/d", "/scripts/main.lua", "drift", "")
		},
		"script discovery": func(c *Client) {
			c.discoverAndSnapshotScripts("t", uuid.New(), "thesada/t/d")
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := &Client{c: silent, cliTimeout: 50 * time.Millisecond}
			start := time.Now()
			pull(c)
			if took := time.Since(start); took > 2*time.Second {
				t.Fatalf("pull gave up after %s, want about the 50ms CLIRequestTimeout", took)
			}
		})
	}
}
