//go:build integration

// Masked firmware reads a secret back as (set) or (empty). The app never sends
// a marker as a value, to either firmware generation.
//
//	go test -tags integration -run TestMaskedConfig ./pkg/web/...
package web

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"
	"time"

	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// maskPasswords is the test's own stand-in for the firmware mask: every
// password leaf reads (set), or (empty) for "", pretty printed.
func maskPasswords(t *testing.T, body string) string {
	t.Helper()
	var m any
	if json.Unmarshal([]byte(body), &m) != nil {
		return body
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				if k == "password" && e != nil {
					if e == "" {
						x[k] = "(empty)"
					} else {
						x[k] = "(set)"
					}
					continue
				}
				walk(e)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(m)
	out, _ := json.MarshalIndent(m, "", "  ")
	return string(out)
}

// serveMaskedCat answers chunked fs.cat over d's files through view.
func serveMaskedCat(fd *mqtttest.FakeDevice, d *deviceFS, view func(string) string) {
	fd.Handle("fs.cat", func(args string, _ []byte) []mqtttest.Response {
		d.mu.Lock()
		defer d.mu.Unlock()
		parts := strings.Fields(args)
		body, ok := d.files[parts[0]]
		if !ok {
			return []mqtttest.Response{{OK: false, Output: []string{"File not found"}}}
		}
		body = view(body)
		total := len(body)
		off, n := total, 0
		if len(parts) == 3 {
			off, _ = strconv.Atoi(parts[1])
			n, _ = strconv.Atoi(parts[2])
		}
		off = min(off, total)
		data := body[off:min(off+n, total)]
		length, done := len(data), off+len(data) >= total
		return []mqtttest.Response{{OK: true, Total: &total, Offset: &off, Length: &length, Done: &done, Data: &data}}
	})
}

func TestMaskedConfigWrite(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	const tenant = "webcfg-masked"
	env.SeedTenant(t, tenant)
	ctx := context.Background()

	type gen struct {
		name   string
		masked bool
	}
	n := 0
	for _, g := range []gen{{"old_firmware", false}, {"masked_firmware", true}} {
		dev := func() (*service.Device, *mqtttest.FakeDevice, *deviceFS) {
			n++
			id := "mask" + strconv.Itoa(n)
			prefix := "thesada/" + tenant + "/" + id
			device := seedDevice(t, env, tenant, id, prefix)
			fd := mqtttest.NewFakeDevice(t, broker, prefix)
			d := serveDeviceFS(fd, map[string]string{"/config.json": `{}`})
			if g.masked {
				serveMaskedCat(fd, d, func(b string) string { return maskPasswords(t, b) })
			}
			return device, fd, d
		}
		write := func(device *service.Device, content string) (requestStatus, string) {
			reqID := s.cliRequests.enqueue()
			claim, _ := s.claimDeviceWrite(device.ID, time.Minute)
			s.runCLIWrite(ctx, reqID, claim, device, "thesada/"+tenant+"/"+device.DeviceID, "/config.json", content, nil)
			e := s.cliRequests.get(reqID)
			if e == nil {
				return "", "no entry"
			}
			return e.Status, e.ErrorMsg
		}

		t.Run(g.name+"/a_posted_marker_goes_out_blank", func(t *testing.T) {
			device, fd, d := dev()
			serveSecretInfo(fd, "mqtt.password          nvs")
			if st, msg := write(device, `{"device":{"name":"(set)"},"mqtt":{"host":"b","password":"(set)"}}`); st != reqStatusDone {
				t.Fatalf("status = %s %q, want done", st, msg)
			}
			got, _ := d.file("/config.json")
			var m map[string]map[string]any
			if err := json.Unmarshal([]byte(got), &m); err != nil {
				t.Fatalf("device file %q: %v", got, err)
			}
			if m["mqtt"]["password"] != "" || m["mqtt"]["host"] != "b" || m["device"]["name"] != "(set)" {
				t.Errorf("device file = %s, want the password blank and the rest as posted", got)
			}
		})

		t.Run(g.name+"/a_marker_the_device_cannot_back_is_refused", func(t *testing.T) {
			device, fd, _ := dev()
			serveSecretInfo(fd, "mqtt.password          config/none")
			if st, msg := write(device, `{"mqtt":{"password":"(set)"}}`); st != reqStatusError || !strings.Contains(msg, "mqtt.password") {
				t.Fatalf("status = %s %q, want a refusal naming mqtt.password", st, msg)
			}
			if c := fd.Calls("fs.write"); c != 0 {
				t.Errorf("fs.write calls = %d, want none", c)
			}
		})

		t.Run(g.name+"/a_blank_secret_saves", func(t *testing.T) {
			device, fd, d := dev()
			serveSecretInfo(fd, "mqtt.password          nvs")
			content := `{"mqtt":{"host":"b","password":""}}`
			if st, msg := write(device, content); st != reqStatusDone {
				t.Fatalf("status = %s %q, want done", st, msg)
			}
			if got, _ := d.file("/config.json"); got != content {
				t.Errorf("device file = %q, want %q", got, content)
			}
		})
	}
}

// Load from device on masked firmware: no marker reaches the editor or the store.
func TestMaskedConfigLoad(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	s := startWebBrokerServer(t, env, broker)
	const tenant = "webcfg-maskload"
	env.SeedTenant(t, tenant)
	ctx := context.Background()
	prefix := "thesada/" + tenant + "/ml1"
	device := seedDevice(t, env, tenant, "ml1", prefix)
	masked := `{"mqtt":{"host":"b","password":"(set)"},"wifi":{"networks":[{"ssid":"cafe","password":"(empty)"}]}}`
	fd := mqtttest.NewFakeDevice(t, broker, prefix)
	fd.ServeChunkedFile("/config.json", masked, 40)

	reqID := s.cliRequests.enqueue()
	s.runConfigLoad(ctx, reqID, device, nil)
	entry := s.cliRequests.get(reqID)
	if entry == nil || entry.Status != reqStatusDone || entry.Response == nil || entry.Response.Data == nil {
		t.Fatalf("entry = %+v, want done", entry)
	}
	shown := *entry.Response.Data
	if service.HasMaskMarker(shown) || !strings.Contains(shown, `"b"`) {
		t.Errorf("editor data = %s, want blanks in place of markers", shown)
	}
	if _, found, _ := env.Services.Secrets.Reveal(ctx, tenant, device.ID, "mqtt.password"); found {
		t.Error("a marker landed in the secret store")
	}
	open, err := env.Services.DeviceFiles.OpenNetworkCurrent(ctx, tenant, device.ID, "cafe")
	if err != nil || !open {
		t.Errorf("cafe open = %v, %v, want open from (empty)", open, err)
	}
}
