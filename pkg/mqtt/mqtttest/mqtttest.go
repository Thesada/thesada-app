//go:build integration

// Package mqtttest provides the shared broker-path integration harness: a
// throwaway mosquitto container and a FakeDevice that answers the firmware
// CLI protocol (envelope unwrap, req_id echo, cli/response publish) so tests
// can drive the full app -> broker -> device -> DB chain without hardware.
// Used by pkg/mqtt and pkg/web integration tests.
package mqtttest

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	paho "github.com/eclipse/paho.mqtt.golang"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// StartMosquitto brings up an eclipse-mosquitto container with the image's
// shipped no-auth config (listener 1883 on all interfaces, anonymous allowed)
// and returns a tcp:// broker URL. Torn down via t.Cleanup.
// in: testing.T. out: broker URL, e.g. "tcp://127.0.0.1:32771".
func StartMosquitto(t *testing.T) string {
	t.Helper()
	ctx := context.Background()

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "eclipse-mosquitto:2",
			ExposedPorts: []string{"1883/tcp"},
			Cmd:          []string{"mosquitto", "-c", "/mosquitto-no-auth.conf"},
			WaitingFor:   wait.ForListeningPort("1883/tcp"),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start mosquitto: %v", err)
	}
	t.Cleanup(func() { _ = ctr.Terminate(context.Background()) })

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatalf("mosquitto host: %v", err)
	}
	port, err := ctr.MappedPort(ctx, "1883/tcp")
	if err != nil {
		t.Fatalf("mosquitto port: %v", err)
	}
	return fmt.Sprintf("tcp://%s:%s", host, port.Port())
}

// Response is one cli/response message a Handler wants published. Fields
// mirror the firmware's CLIResponse JSON; zero-value fields are omitted.
type Response struct {
	OK     bool     `json:"ok"`
	Output []string `json:"output,omitempty"`
	Page   *int     `json:"page,omitempty"`
	More   *bool    `json:"more,omitempty"`
	Total  *int     `json:"total,omitempty"`
	Offset *int     `json:"offset,omitempty"`
	Length *int     `json:"length,omitempty"`
	Done   *bool    `json:"done,omitempty"`
	Data   *string  `json:"data,omitempty"`
}

// Handler answers one CLI command. args is the unwrapped envelope args (or ""
// for a raw binary payload); raw is the exact payload bytes for binary
// protocols (fs.write: "path\ncontent"). Every returned Response is published
// to cli/response in order, req_id echoed when the request carried one.
type Handler func(args string, raw []byte) []Response

// FakeDevice is a paho client subscribed to <prefix>/cli/# that answers
// registered commands the way firmware would. Unhandled commands get
// {"ok":false} so a missing registration fails a test loudly, not by timeout.
type FakeDevice struct {
	t      *testing.T
	c      paho.Client
	prefix string

	mu       sync.Mutex
	handlers map[string]Handler
	calls    map[string]int
}

// NewFakeDevice connects a fake device for topicPrefix (e.g. "thesada/t1/dev1")
// and subscribes to its CLI tree. Torn down via t.Cleanup.
// in: t, broker URL, device topic prefix. out: ready *FakeDevice.
func NewFakeDevice(t *testing.T, brokerURL, topicPrefix string) *FakeDevice {
	t.Helper()
	fd := &FakeDevice{
		t:        t,
		prefix:   topicPrefix,
		handlers: make(map[string]Handler),
		calls:    make(map[string]int),
	}

	opts := paho.NewClientOptions().
		AddBroker(brokerURL).
		SetClientID("fake-" + strings.ReplaceAll(topicPrefix, "/", "-")).
		SetOrderMatters(false)
	fd.c = paho.NewClient(opts)
	// WaitTimeout returning false means timed out with Error() still nil -
	// the timeout must be checked first or it is silently swallowed.
	if tok := fd.c.Connect(); !tok.WaitTimeout(10 * time.Second) {
		t.Fatal("fake device connect: timed out")
	} else if tok.Error() != nil {
		t.Fatalf("fake device connect: %v", tok.Error())
	}
	t.Cleanup(func() { fd.c.Disconnect(250) })

	cliTree := topicPrefix + "/cli/#"
	if tok := fd.c.Subscribe(cliTree, 0, fd.onCommand); !tok.WaitTimeout(10 * time.Second) {
		t.Fatalf("fake device subscribe %s: timed out", cliTree)
	} else if tok.Error() != nil {
		t.Fatalf("fake device subscribe %s: %v", cliTree, tok.Error())
	}
	return fd
}

// WaitForLive blocks until the subscribing client receives its own publish on
// probeTopic - proof the subscription tree is live (IsConnected alone races
// the SUBACK). registerTap and publish adapt the app mqtt client; mqtttest
// cannot import pkg/mqtt directly without cycling through that package's own
// in-package integration tests.
func WaitForLive(t *testing.T, probeTopic string,
	registerTap func(pattern string, sink func(topic string, payload []byte, retained bool, qos byte)) (func(), error),
	publish func(topic string, payload []byte, qos byte, retain bool) error,
) {
	t.Helper()
	probe := make(chan struct{}, 8)
	cancel, err := registerTap(probeTopic, func(string, []byte, bool, byte) {
		select {
		case probe <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatalf("register probe tap: %v", err)
	}
	defer cancel()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_ = publish(probeTopic, []byte("ping"), 0, false) // lost pings just retry
		select {
		case <-probe:
			return
		case <-time.After(200 * time.Millisecond):
		}
	}
	t.Fatal("mqtt client never saw its own probe - subscription not live")
}

// Handle registers (or replaces) the handler for one CLI command name.
func (fd *FakeDevice) Handle(cmd string, h Handler) {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	fd.handlers[cmd] = h
}

// Calls reports how many times cmd has been invoked.
func (fd *FakeDevice) Calls(cmd string) int {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	return fd.calls[cmd]
}

// OK is shorthand for a single successful response with output lines.
func OK(output ...string) []Response {
	return []Response{{OK: true, Output: output}}
}

// onCommand unwraps the request envelope, runs the handler, and publishes
// each response with the request's req_id echoed - exactly the contract the
// app's CLIRequest/CLIRequestRaw correlation relies on.
func (fd *FakeDevice) onCommand(_ paho.Client, msg paho.Message) {
	topic := msg.Topic()
	cmd := strings.TrimPrefix(topic, fd.prefix+"/cli/")
	if cmd == "response" || strings.Contains(cmd, "/") {
		return
	}

	var env struct {
		ReqID string `json:"req_id"`
		Args  string `json:"args"`
	}
	args := ""
	raw := msg.Payload()
	if err := json.Unmarshal(raw, &env); err == nil && (env.ReqID != "" || env.Args != "") {
		args = env.Args
		raw = []byte(env.Args)
	}

	fd.mu.Lock()
	h := fd.handlers[cmd]
	fd.calls[cmd]++
	fd.mu.Unlock()

	responses := []Response{{OK: false, Output: []string{"fake device: no handler for " + cmd}}}
	if h != nil {
		responses = h(args, raw)
	}

	for _, resp := range responses {
		body := map[string]any{"cmd": cmd, "ok": resp.OK}
		if env.ReqID != "" {
			body["req_id"] = env.ReqID
		}
		if resp.Output != nil {
			body["output"] = resp.Output
		}
		for k, v := range map[string]any{
			"page": resp.Page, "more": resp.More, "total": resp.Total,
			"offset": resp.Offset, "length": resp.Length, "done": resp.Done, "data": resp.Data,
		} {
			switch p := v.(type) {
			case *int:
				if p != nil {
					body[k] = *p
				}
			case *bool:
				if p != nil {
					body[k] = *p
				}
			case *string:
				if p != nil {
					body[k] = *p
				}
			}
		}
		payload, err := json.Marshal(body)
		if err != nil {
			fd.t.Errorf("fake device marshal response: %v", err)
			return
		}
		// Errorf, not Fatalf: this runs on a paho callback goroutine. A lost
		// response must still be named - the caller otherwise just times out
		// with no hint the fake device failed to answer.
		if tok := fd.c.Publish(fd.prefix+"/cli/response", 0, false, payload); !tok.WaitTimeout(5 * time.Second) {
			fd.t.Errorf("fake device response publish: timed out")
		} else if tok.Error() != nil {
			fd.t.Errorf("fake device response publish: %v", tok.Error())
		}
	}
}

// ServeChunkedFile registers an fs.cat handler that serves content in
// chunkSize pieces honoring the firmware "path offset len" argument shape -
// the exact protocol pullAndSnapshot's chunk loop speaks.
// in: file path the handler answers for, its content, chunk size.
func (fd *FakeDevice) ServeChunkedFile(path, content string, chunkSize int) {
	fd.Handle("fs.cat", func(args string, _ []byte) []Response {
		fields := strings.Fields(args)
		if len(fields) < 1 || fields[0] != path {
			return []Response{{OK: false, Output: []string{"no such file: " + args}}}
		}
		offset := 0
		if len(fields) >= 2 {
			if _, err := fmt.Sscanf(fields[1], "%d", &offset); err != nil {
				return []Response{{OK: false, Output: []string{"bad offset: " + fields[1]}}}
			}
		}
		if offset > len(content) {
			offset = len(content)
		}
		end := offset + chunkSize
		if end > len(content) {
			end = len(content)
		}
		chunk := content[offset:end]
		length := len(chunk)
		total := len(content)
		done := end >= len(content)
		return []Response{{
			OK: true, Data: &chunk, Offset: &offset, Length: &length, Total: &total, Done: &done,
		}}
	})
}
