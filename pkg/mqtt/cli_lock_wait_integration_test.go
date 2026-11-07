//go:build integration

// A CLI request whose deadline runs out while it waits for the device lock
// must not still publish its command. A stagedWrite step that already
// reported a timeout would otherwise land on the device afterwards.
//
//	go test -tags integration -run TestCLIRequest_DeadlineSpentInLockQueue ./pkg/mqtt/...
package mqtt

import (
	"context"
	"errors"
	"testing"
	"time"

	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
)

func TestCLIRequest_DeadlineSpentInLockQueueSendsNothing(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	c := startBrokerClient(t, env, broker)

	const tenant = "lockq1"
	env.SeedTenant(t, tenant)
	if err := env.Services.Tenants.Refresh(); err != nil {
		t.Fatalf("refresh tenant slugs: %v", err)
	}
	prefix := "thesada/" + tenant + "/dev1"
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.Handle("fs.mv", func(string, []byte) []mqtttest.Response { return mqtttest.OK("Renamed /a -> /b") })
	fd.Handle("fs.write", func(string, []byte) []mqtttest.Response { return mqtttest.OK("Wrote 1 bytes to /a") })

	sends := []struct {
		cmd  string
		send func(context.Context) error
	}{
		{"fs.mv", func(ctx context.Context) error {
			_, err := c.CLIRequest(ctx, prefix, "fs.mv", "/a /b")
			return err
		}},
		{"fs.write", func(ctx context.Context) error {
			_, err := c.CLIRequestRaw(ctx, prefix, "fs.write", []byte("/a\nx"))
			return err
		}},
	}
	for _, s := range sends {
		lock := c.cliLockFor(prefix)
		lock.Lock()
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		done := make(chan error, 1)
		go func() { done <- s.send(ctx) }()
		time.Sleep(300 * time.Millisecond)
		lock.Unlock()
		err := <-done
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s: err = %v, want the deadline", s.cmd, err)
		}
	}
	// Room for a stray publish to reach the fake device before counting.
	time.Sleep(time.Second)
	for _, s := range sends {
		if n := fd.Calls(s.cmd); n != 0 {
			t.Fatalf("%s reached the device %d time(s) after its deadline", s.cmd, n)
		}
	}

	// Control: with a live deadline the same commands do reach the device.
	for _, s := range sends {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		err := s.send(ctx)
		cancel()
		if err != nil || fd.Calls(s.cmd) != 1 {
			t.Fatalf("%s control: err=%v calls=%d, want one delivered", s.cmd, err, fd.Calls(s.cmd))
		}
	}
}
