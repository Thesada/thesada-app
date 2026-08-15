//go:build integration

// CLI topic split: the app must get a response from a device whichever side of
// the migration that device is on. Runs the real broker path so the topic
// wiring is exercised, not mocked.
//
//	go test -tags integration -run TestCLITopicSplit ./pkg/mqtt/...
package mqtt

import (
	"context"
	"testing"
	"time"

	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
)

func TestCLITopicSplit_RespondsOnEitherTopic(t *testing.T) {
	cases := []struct {
		name string
		mode mqtttest.CLIResponseMode
	}{
		{"new firmware, new topic only", mqtttest.RespondNewOnly},
		{"old firmware, legacy topic only", mqtttest.RespondLegacyOnly},
		// Not a fleet state - a duplicate-response robustness case.
		{"device answering on both topics", mqtttest.RespondDual},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := servicetest.Start(t)
			broker := mqtttest.StartMosquitto(t)
			c := startBrokerClient(t, env, broker)

			const tenant = "split1"
			env.SeedTenant(t, tenant)
			if err := env.Services.Tenants.Refresh(); err != nil {
				t.Fatalf("refresh tenant slugs: %v", err)
			}
			prefix := "thesada/" + tenant + "/dev1"

			fd := mqtttest.NewFakeDevice(t, broker, prefix)
			fd.SetCLIResponseMode(tc.mode)
			fd.Handle("config.dump", func(string, []byte) []mqtttest.Response {
				return mqtttest.OK("hello")
			})

			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			resp, err := c.CLIRequest(ctx, prefix, "config.dump", "")
			if err != nil {
				t.Fatalf("CLIRequest: %v", err)
			}
			if !resp.OK {
				t.Fatalf("response not ok: %+v", resp)
			}
			// Dual-publish sends the same page twice. Page assembly assigns by
			// page index rather than appending, so the duplicate overwrites
			// itself - the output must not be doubled.
			if len(resp.Output) != 1 || resp.Output[0] != "hello" {
				t.Fatalf("got output %q, want exactly one \"hello\"", resp.Output)
			}
			if fd.Calls("config.dump") != 1 {
				t.Errorf("device saw %d commands, want 1", fd.Calls("config.dump"))
			}
		})
	}
}

// Back-to-back requests with a duplicate in flight. CLIRequestRaw does no req_id
// filtering - its correlation rests on exactly one response per request - so a
// duplicate left in flight by the first call gets consumed by the second as if
// it were the second's reply. The visible damage is a device error read as the
// previous command's success.
func TestCLITopicSplit_DuplicateDoesNotLeakIntoNextRequest(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	c := startBrokerClient(t, env, broker)

	const tenant = "split3"
	env.SeedTenant(t, tenant)
	if err := env.Services.Tenants.Refresh(); err != nil {
		t.Fatalf("refresh tenant slugs: %v", err)
	}
	prefix := "thesada/" + tenant + "/dev1"

	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.SetCLIResponseMode(mqtttest.RespondDual)
	fd.Handle("fs.write", func(string, []byte) []mqtttest.Response {
		return mqtttest.OK("written")
	})
	fd.Handle("fs.append", func(string, []byte) []mqtttest.Response {
		return []mqtttest.Response{{OK: false, Output: []string{"disk full"}}}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	first, err := c.CLIRequestRaw(ctx, prefix, "fs.write", []byte("/f.lua\nAAA"))
	if err != nil {
		t.Fatalf("fs.write: %v", err)
	}
	if !first.OK {
		t.Fatalf("fs.write not ok: %+v", first)
	}

	second, err := c.CLIRequestRaw(ctx, prefix, "fs.append", []byte("/f.lua\nBBB"))
	if err != nil {
		t.Fatalf("fs.append: %v", err)
	}
	if second.OK {
		t.Fatalf("fs.append reported ok - it consumed the fs.write duplicate: %+v", second)
	}
	if len(second.Output) == 0 || second.Output[0] != "disk full" {
		t.Fatalf("got output %q, want the device error", second.Output)
	}
}

// A paged response with duplicates is where a naive append would corrupt the
// output: every page arrives twice.
func TestCLITopicSplit_PagedDuringDualPublish(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	c := startBrokerClient(t, env, broker)

	const tenant = "split2"
	env.SeedTenant(t, tenant)
	if err := env.Services.Tenants.Refresh(); err != nil {
		t.Fatalf("refresh tenant slugs: %v", err)
	}
	prefix := "thesada/" + tenant + "/dev1"

	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.SetCLIResponseMode(mqtttest.RespondDual)
	fd.Handle("fs.ls", func(string, []byte) []mqtttest.Response {
		page0, page1 := 0, 1
		more := true
		notMore := false
		return []mqtttest.Response{
			{OK: true, Output: []string{"line-a"}, Page: &page0, More: &more},
			{OK: true, Output: []string{"line-b"}, Page: &page1, More: &notMore},
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := c.CLIRequest(ctx, prefix, "fs.ls", "")
	if err != nil {
		t.Fatalf("CLIRequest: %v", err)
	}
	want := []string{"line-a", "line-b"}
	if len(resp.Output) != len(want) {
		t.Fatalf("got %q, want %q - duplicate pages leaked into the output", resp.Output, want)
	}
	for i := range want {
		if resp.Output[i] != want[i] {
			t.Fatalf("got %q, want %q", resp.Output, want)
		}
	}
}
