//go:build integration

// A device reply that feeds a stored fact must echo the request's req_id (Q4).
//
//	go test -tags integration -run TestBrokerUncorrelated ./pkg/mqtt/...
package mqtt

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
)

// TestBrokerUncorrelatedRepliesAreNotStored: a reply without the echoed req_id may answer an
// earlier request, so drift pulls and chunked reads store nothing from it.
func TestBrokerUncorrelatedRepliesAreNotStored(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	c := startBrokerClient(t, env, broker)

	const tenant = "brk-corr"
	env.SeedTenant(t, tenant)
	prefix := "thesada/" + tenant + "/dev1"
	ctx := context.Background()
	devicePk, err := env.Services.Devices.Upsert(tenant, "dev1", "", "", "", prefix)
	if err != nil {
		t.Fatalf("seed device: %v", err)
	}
	fd := mqtttest.NewFakeDevice(t, broker, prefix)

	t.Run("an_uncorrelated_config_dump_is_not_stored", func(t *testing.T) {
		configJSON := `{"a":1}`
		fd.Handle("config.dump", func(string, []byte) []mqtttest.Response { return mqtttest.OK(configJSON) })
		fd.OmitReqID(true, "config.dump")
		defer fd.OmitReqID(false, "config.dump")
		c.pullAndSnapshot(tenant, devicePk, prefix, "config.json", "drift", sha256Hex(configJSON))
		if snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "config.json"); err != nil || snap != nil {
			t.Fatalf("Latest(config.json) = %+v, %v, want nothing stored", snap, err)
		}
	})

	t.Run("an_uncorrelated_fs_cat_chunk_fails_the_read", func(t *testing.T) {
		fd.ServeChunkedFile("/scripts/u.lua", strings.Repeat("y", 40), 16)
		fd.OmitReqID(true, "fs.cat")
		defer fd.OmitReqID(false, "fs.cat")
		if got, err := c.ReadFileChunked(ctx, prefix, "/scripts/u.lua", 5*time.Second); err == nil {
			t.Fatalf("ReadFileChunked = %q, want an error for an uncorrelated chunk", got)
		}
		c.pullAndSnapshot(tenant, devicePk, prefix, "/scripts/u.lua", "drift", "")
		if snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "/scripts/u.lua"); err != nil || snap != nil {
			t.Fatalf("Latest(u.lua) = %+v, %v, want nothing stored", snap, err)
		}
	})

	t.Run("a_correlated_read_still_stores", func(t *testing.T) {
		c.pullAndSnapshot(tenant, devicePk, prefix, "/scripts/u.lua", "drift", "")
		if snap, err := env.Services.DeviceFiles.Latest(ctx, tenant, devicePk, "/scripts/u.lua"); err != nil || snap == nil {
			t.Fatalf("Latest(u.lua) = %+v, %v, want the correlated read stored", snap, err)
		}
	})

	t.Run("cli_request_stateful_refuses_an_uncorrelated_reply", func(t *testing.T) {
		fd.Handle("version", func(string, []byte) []mqtttest.Response { return mqtttest.OK("v1.4.4") })
		fd.OmitReqID(true, "version")
		defer fd.OmitReqID(false, "version")
		resp, err := c.CLIRequestStateful(ctx, prefix, "version", "")
		if !errors.Is(err, ErrUncorrelated) || resp == nil || resp.Correlated {
			t.Fatalf("CLIRequestStateful = %+v, %v, want the reply with ErrUncorrelated", resp, err)
		}
		resp, err = c.CLIRequest(ctx, prefix, "version", "")
		if err != nil || resp.Correlated {
			t.Fatalf("CLIRequest = %+v, %v, want the reply, not correlated", resp, err)
		}
	})
}
