// Package mqtt subscribes to thesada/+/+/# and writes heartbeats, telemetry,
// and alerts into Postgres. Single subscriber, single connection.
package mqtt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	// Eclipse Paho MQTT Go client is dual-licensed EPL-2.0 / EDL-1.0. We
	// use it under the Eclipse Distribution License v1.0 (BSD-3-Clause
	// equivalent), which is compatible with this app's AGPL-3.0-only
	// licence. The selection is recorded in THIRD_PARTY_LICENSES at the
	// repo root.
	mqttlib "github.com/eclipse/paho.mqtt.golang"
	"github.com/google/uuid"

	"thesada.app/app/pkg/alerts"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/ws"
)

// Client wraps a paho MQTT client plus the dependencies its message handlers need.
// Created by Start, torn down with Stop.
type Client struct {
	c        mqttlib.Client
	pool     *db.Pool
	notifier *alerts.Notifier
	hub      *ws.Hub
	services *service.Services
	root     string

	// Fan-out tap registry for the /admin/mqtt shell. Each registered tap
	// has a compiled wildcard matcher and a sink callback; onMessage forwards
	// every message whose topic matches at least one tap. Guarded by mu.
	mu     sync.RWMutex
	tapSeq atomic.Uint64
	taps   map[uint64]*mqttTap

	// Per-device retained-topic manifests. Each
	// device publishes a JSON array at <topic_prefix>/info/retained_topics
	// listing every topic it owns as retained. Cached here on receipt so
	// device-delete can issue empty retained payloads to clear
	// the broker state. Keyed by topic prefix, e.g. "thesada/default/sht31".
	// Guarded by manifestMu; populated from onMessage.
	manifestMu     sync.RWMutex
	retainedTopics map[string][]string

	// Per-device CLI request serialization. Two concurrent CLIRequests
	// against the same device share the cli/response topic and race for
	// the next published payload; the loser sees the wrong response.
	// Hold cliLockFor(topicPrefix) for the duration of every CLI call so
	// only one is in flight per device at a time. req_id correlation
	// (firmware v1.4.5+) is belt-and-suspenders for retained replays /
	// out-of-order delivery, not the primary defence.
	cliMu    sync.Mutex
	cliLocks map[string]*sync.Mutex
}

// mqttTap is a single subscriber bolted onto the running Client. Sink must
// be non-blocking - implementations are expected to push into a bounded
// channel and drop on back-pressure. The matcher honors MQTT `+` and `#`
// wildcards, same rules as paho.
type mqttTap struct {
	id      uint64
	pattern string
	matcher func(topic string) bool
	sink    TapSink
}

// TapSink is the callback a /admin/mqtt websocket handler registers to
// receive live MQTT messages that match its pattern.
type TapSink func(topic string, payload []byte, retained bool, qos byte)

// ErrTapPattern is returned by RegisterTap when the pattern does not compile
// into a valid MQTT topic filter.
var ErrTapPattern = errors.New("invalid mqtt topic pattern")

// compileMQTTMatcher turns an MQTT topic filter (with + and # wildcards)
// into a function that tests whether a published topic matches.
//
// Validation follows MQTT 3.1.1 section 4.7:
//   - The filter must not be empty.
//   - `+` (single-level wildcard) must occupy an entire level on its own,
//     bounded by `/`, string start, or string end. Segments that mix `+` with
//     literal characters (e.g. "+foo", "bar+", "a+b") are rejected.
//   - `#` (multi-level wildcard) must be the last character in the filter.
//     It must either be the entire filter ("# ") or be its own level preceded
//     by a `/` (e.g. "thesada/#"). A `#` embedded in a segment with other
//     characters (e.g. "foo#", "a#b") or appearing before the end of the
//     filter (e.g. "#/bar") is rejected.
//   - Consecutive level separators ("//") produce empty segments. These are
//     valid in topic names per the spec but are rejected here as they are
//     almost always an operator mistake when constructing a filter at runtime.
//
// in: pattern string. out: matcher func, error if the pattern is malformed.
func compileMQTTMatcher(pattern string) (func(string) bool, error) {
	if pattern == "" {
		return nil, fmt.Errorf("%w: filter must not be empty", ErrTapPattern)
	}
	parts := strings.Split(pattern, "/")
	for i, p := range parts {
		switch {
		case p == "":
			// The very first segment may be empty only for a leading-slash
			// filter (e.g. "/sport"), which is spec-valid. An empty segment
			// anywhere else (from "//") is almost always a bug.
			if i != 0 {
				return nil, fmt.Errorf("%w: empty segment at level %d (consecutive '/' separators are not allowed in filters)", ErrTapPattern, i)
			}
		case p == "#":
			if i != len(parts)-1 {
				return nil, fmt.Errorf("%w: '#' at level %d is not the last level - '#' must only appear as the final segment (MQTT 3.1.1 s4.7.1)", ErrTapPattern, i)
			}
		case strings.Contains(p, "#"):
			return nil, fmt.Errorf("%w: level %d %q mixes '#' with other characters - '#' must occupy an entire level on its own", ErrTapPattern, i, p)
		case strings.Contains(p, "+"):
			if p != "+" {
				return nil, fmt.Errorf("%w: level %d %q mixes '+' with other characters - '+' must occupy an entire level on its own", ErrTapPattern, i, p)
			}
		}
	}
	return func(topic string) bool {
		tp := strings.Split(topic, "/")
		for i, p := range parts {
			if p == "#" {
				return true
			}
			if i >= len(tp) {
				return false
			}
			if p == "+" {
				continue
			}
			if p != tp[i] {
				return false
			}
		}
		return len(tp) == len(parts)
	}, nil
}

// RegisterTap attaches a TapSink to the running client. Pattern is an MQTT
// wildcard filter (+ and #). Returns a cancel func the caller runs to
// detach; always call it via defer on the handler shutdown path.
// in: pattern, sink. out: cancel, error.
func (c *Client) RegisterTap(pattern string, sink TapSink) (func(), error) {
	matcher, err := compileMQTTMatcher(pattern)
	if err != nil {
		return nil, err
	}
	id := c.tapSeq.Add(1)
	tap := &mqttTap{id: id, pattern: pattern, matcher: matcher, sink: sink}
	c.mu.Lock()
	if c.taps == nil {
		c.taps = make(map[uint64]*mqttTap)
	}
	c.taps[id] = tap
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.taps, id)
		c.mu.Unlock()
	}, nil
}

// fanoutTaps dispatches one inbound MQTT message to every tap whose pattern
// matches. Runs in the paho callback goroutine; sinks must be fast and
// non-blocking (push into a channel + drop on full).
// in: topic, payload, retained flag, qos. out: none.
func (c *Client) fanoutTaps(topic string, payload []byte, retained bool, qos byte) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, t := range c.taps {
		if t.matcher(topic) {
			t.sink(topic, payload, retained, qos)
		}
	}
}

// PublishRaw forwards a publish through the shared paho client without any
// topic validation - that's the caller's responsibility (the /admin/mqtt
// handler enforces the tenant prefix guard and the audit log).
// in: topic, payload, qos, retain. out: error from paho.
func (c *Client) PublishRaw(topic string, payload []byte, qos byte, retain bool) error {
	if c.c == nil || !c.c.IsConnected() {
		return errors.New("mqtt client not connected")
	}
	t := c.c.Publish(topic, qos, retain, payload)
	t.WaitTimeout(5 * time.Second)
	return t.Error()
}

// CLIResponse is the parsed JSON response from a device CLI command.
type CLIResponse struct {
	Cmd    string   `json:"cmd"`
	ReqID  string   `json:"req_id,omitempty"`
	OK     bool     `json:"ok"`
	Output []string `json:"output,omitempty"`
	// Pagination fields (firmware v1.4.6+). A command whose output
	// overflows the device publish buffer is split across multiple
	// cli/response messages, each with a 0-indexed Page and a More flag;
	// the final page carries More=false. Pre-1.4.6 firmware omits both
	// and the single message is the whole response. CLIRequest /
	// CLIRequestRaw accumulate pages transparently, so a CLIResponse
	// they return always has Page/More nil and Output holding the
	// concatenated result.
	Page *int  `json:"page,omitempty"`
	More *bool `json:"more,omitempty"`
	// Chunked fs.cat fields (present when offset/length requested)
	Total  *int    `json:"total,omitempty"`
	Offset *int    `json:"offset,omitempty"`
	Length *int    `json:"length,omitempty"`
	Done   *bool   `json:"done,omitempty"`
	Data   *string `json:"data,omitempty"`
}

// awaitPagedCLIResponse reads cli/response payloads off ch and assembles a
// complete CLIResponse. Firmware v1.4.6+ paginates oversized output across
// multiple messages (0-indexed Page, More flag; the final page carries
// More=false). This concatenates each page's Output in Page order and
// returns once the final page and every lower-indexed page have arrived.
// Single-page responses and pre-1.4.6 firmware (no Page/More) return on
// the first message. Pages may arrive out of order - the assembly is
// keyed by Page index, not arrival order. The returned CLIResponse has
// Page/More cleared.
// in: ctx, ch (raw cli/response payload bytes). out: assembled *CLIResponse, error.
func awaitPagedCLIResponse(ctx context.Context, ch <-chan []byte) (*CLIResponse, error) {
	pages := make(map[int][]string)
	var (
		final     CLIResponse
		haveFinal bool
	)
	for {
		select {
		case raw := <-ch:
			var resp CLIResponse
			if err := json.Unmarshal(raw, &resp); err != nil {
				return nil, fmt.Errorf("parse response: %w", err)
			}
			page := 0
			if resp.Page != nil {
				page = *resp.Page
			}
			pages[page] = resp.Output
			// More absent or false marks the last page. Older firmware
			// omits More entirely, so its single message is the final
			// (and only) page.
			if resp.More == nil || !*resp.More {
				final = resp
				haveFinal = true
			}
			if !haveFinal {
				continue
			}
			finalIdx := 0
			if final.Page != nil {
				finalIdx = *final.Page
			}
			combined := make([]string, 0)
			complete := true
			for i := 0; i <= finalIdx; i++ {
				pg, ok := pages[i]
				if !ok {
					complete = false
					break
				}
				combined = append(combined, pg...)
			}
			if !complete {
				continue
			}
			final.Output = combined
			final.Page = nil
			final.More = nil
			return &final, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// cliEnvelope wraps a CLI command payload so the firmware (v1.4.5+) can
// echo req_id back on cli/response for correlation. Older firmware ignores
// unknown fields and runs the command with the envelope JSON as a literal
// arg - so on a mixed-version fleet, the per-device mutex remains the
// load-bearing defence. The firmware unwraps `args` and runs the command
// with that as the raw payload (binary protocols see the same path\n
// content / type\nPEM bytes inside the args string).
type cliEnvelope struct {
	ReqID string `json:"req_id"`
	Args  string `json:"args"`
}

// cliLockFor returns a mutex unique to the given device. Lazily initialised
// so the map never grows beyond devices that actually receive CLI traffic.
// Caller must Lock/Unlock; held for the duration of one CLIRequest.
// in: topic prefix. out: mutex pointer (never nil).
func (c *Client) cliLockFor(topicPrefix string) *sync.Mutex {
	c.cliMu.Lock()
	defer c.cliMu.Unlock()
	if c.cliLocks == nil {
		c.cliLocks = make(map[string]*sync.Mutex)
	}
	m, ok := c.cliLocks[topicPrefix]
	if !ok {
		m = &sync.Mutex{}
		c.cliLocks[topicPrefix] = m
	}
	return m
}

// CLIRequest sends a CLI command to a device via MQTT and waits for the
// response. topicPrefix is the device's full MQTT prefix (e.g.
// "thesada/acme/owb"). command is the CLI command name (e.g.
// "fs.cat", "config.dump"). payload is the command argument (empty string
// for no-arg commands). Context controls the timeout.
//
// Per-device serialization: holds cliLockFor(topicPrefix) for the duration
// of the call so two concurrent CLIRequests against the same device do not
// race on the shared cli/response topic. req_id correlation (firmware
// v1.4.5+) filters out late or retained-replay responses with a different
// id so the second call cannot accidentally consume the first call's
// late reply. Older firmware that ignores req_id still works - the mutex
// alone makes the response unambiguous.
// in: ctx, topicPrefix, command, payload. out: *CLIResponse, error.
func (c *Client) CLIRequest(ctx context.Context, topicPrefix, command, payload string) (*CLIResponse, error) {
	if c.c == nil || !c.c.IsConnected() {
		return nil, errors.New("mqtt client not connected")
	}

	lock := c.cliLockFor(topicPrefix)
	lock.Lock()
	defer lock.Unlock()

	reqID := uuid.NewString()
	env, err := json.Marshal(cliEnvelope{ReqID: reqID, Args: payload})
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}

	respTopic := topicPrefix + "/cli/response"
	// Buffered well past any realistic page count so the non-blocking
	// tap send below never drops an intermediate page of a paginated
	// response (firmware v1.4.6+).
	ch := make(chan []byte, 64)
	cancel, err := c.RegisterTap(respTopic, func(_ string, p []byte, _ bool, _ byte) {
		// Filter on req_id when present. Firmware v1.4.5+ echoes req_id
		// for every CLI envelope; older firmware omits it. Either is
		// acceptable here - the per-device mutex already guarantees at
		// most one outstanding request, so a response without req_id is
		// always the response we just published.
		var probe struct {
			ReqID string `json:"req_id"`
		}
		_ = json.Unmarshal(p, &probe)
		if probe.ReqID != "" && probe.ReqID != reqID {
			return
		}
		select {
		case ch <- append([]byte(nil), p...):
		default:
		}
	})
	if err != nil {
		return nil, fmt.Errorf("register tap: %w", err)
	}
	defer cancel()

	cmdTopic := topicPrefix + "/cli/" + command
	if err := c.PublishRaw(cmdTopic, env, 0, false); err != nil {
		return nil, fmt.Errorf("publish: %w", err)
	}

	return awaitPagedCLIResponse(ctx, ch)
}

// CLIRequestRaw sends a CLI command with a raw byte payload (for fs.write
// and fs.append where the payload contains path + newline + binary content).
// Firmware binary handlers read payload as raw bytes and would not parse a
// JSON envelope, so this path does not wrap. The per-device mutex still
// serializes against any concurrent CLIRequest on the same device.
// in: ctx, topicPrefix, command, rawPayload. out: *CLIResponse, error.
func (c *Client) CLIRequestRaw(ctx context.Context, topicPrefix, command string, rawPayload []byte) (*CLIResponse, error) {
	if c.c == nil || !c.c.IsConnected() {
		return nil, errors.New("mqtt client not connected")
	}

	lock := c.cliLockFor(topicPrefix)
	lock.Lock()
	defer lock.Unlock()

	respTopic := topicPrefix + "/cli/response"
	// Buffered well past any realistic page count so the non-blocking
	// tap send below never drops an intermediate page of a paginated
	// response (firmware v1.4.6+).
	ch := make(chan []byte, 64)
	cancel, err := c.RegisterTap(respTopic, func(_ string, p []byte, _ bool, _ byte) {
		select {
		case ch <- append([]byte(nil), p...):
		default:
		}
	})
	if err != nil {
		return nil, fmt.Errorf("register tap: %w", err)
	}
	defer cancel()

	cmdTopic := topicPrefix + "/cli/" + command
	pubPayload := rawPayload
	// SIM7080G modem-native MQTT silently drops +SMSUB: URCs for empty-
	// payload publishes (verified 2026-05-08 against LilyGO vendor reference
	// firmware on the same broker / SIM / cellular session). Substitute "{}"
	// so the URC always fires; firmware binary handlers treat an empty
	// payload the same as missing args.
	if len(pubPayload) == 0 {
		pubPayload = []byte("{}")
	}
	if err := c.PublishRaw(cmdTopic, pubPayload, 0, false); err != nil {
		return nil, fmt.Errorf("publish: %w", err)
	}

	return awaitPagedCLIResponse(ctx, ch)
}

// Start connects to the MQTT broker and subscribes to the tenant topic tree.
// in: ctx, cfg, db pool, alerts notifier, ws hub, services. out: running *Client (no-op if MQTT URL empty), or error.
func Start(ctx context.Context, cfg *config.Config, pool *db.Pool, notifier *alerts.Notifier, hub *ws.Hub, services *service.Services) (*Client, error) {
	if cfg.MQTTBrokerURL == "" {
		slog.Warn("MQTT broker URL not set, subscriber disabled")
		return &Client{}, nil
	}
	cli := &Client{pool: pool, notifier: notifier, hub: hub, services: services, root: cfg.MQTTTopicRoot}
	opts := buildMQTTOptions(cfg, cli)

	c := mqttlib.NewClient(opts)
	cli.c = c
	// Don't block startup on the broker. paho already has SetAutoReconnect +
	// SetConnectRetry, so it keeps trying in the background. The publish
	// helpers (PublishRaw, CLIRequest, CLIRequestRaw) all guard on
	// IsConnected so a not-yet-connected client cleanly errors per call
	// instead of crashing the app.
	c.Connect()
	return cli, nil
}

// buildMQTTOptions assembles the paho ClientOptions for the broker connection.
// in: cfg, owning Client (for the OnConnect subscribe callback). out: configured *mqttlib.ClientOptions.
func buildMQTTOptions(cfg *config.Config, cli *Client) *mqttlib.ClientOptions {
	opts := mqttlib.NewClientOptions().
		AddBroker(cfg.MQTTBrokerURL).
		SetClientID(cfg.MQTTClientID).
		SetUsername(cfg.MQTTUsername).
		SetPassword(cfg.MQTTPassword).
		SetAutoReconnect(true).
		SetConnectRetry(true).
		SetConnectRetryInterval(5 * time.Second).
		SetOrderMatters(false)

	opts.OnConnect = func(c mqttlib.Client) {
		// Subscribe to the full tree so both tenant-prefixed (thesada/<tenant>/<device>/...)
		// and legacy tenant-less (thesada/<device>/...) topics are ingested,
		// plus the dynsec response topic so pkg/mqtt/dynsec.go can read
		// createClient/createRole/etc. replies.
		subs := map[string]byte{
			cfg.MQTTTopicRoot + "/#":                1,
			"$CONTROL/dynamic-security/v1/response": 1,
		}
		if t := c.SubscribeMultiple(subs, cli.onMessage); t.Wait() && t.Error() != nil {
			slog.Error("mqtt subscribe failed", "topics", subs, "err", t.Error())
			return
		}
		slog.Info("mqtt subscribed", "topics", subs)
	}
	return opts
}

// Stop disconnects the MQTT client cleanly with a 500ms quiesce window.
// in: receiver. out: none.
func (c *Client) Stop() {
	if c.c != nil && c.c.IsConnected() {
		c.c.Disconnect(500)
	}
}

// cacheRetainedManifest stores the device's retained-topics manifest
// (firmware) keyed by the device's MQTT topic prefix. Called from
// onMessage when a retained `<prefix>/info/retained_topics` arrives.
// Empty payload (cleared on the broker) wipes the cached entry. JSON
// parse failures are logged at debug and the cache is left untouched.
// in: topicPrefix (e.g. "thesada/default/sht31"), JSON-array payload.
// out: none. side effect: c.retainedTopics[topicPrefix] updated.
func (c *Client) cacheRetainedManifest(topicPrefix string, payload []byte) {
	c.manifestMu.Lock()
	defer c.manifestMu.Unlock()
	if c.retainedTopics == nil {
		c.retainedTopics = make(map[string][]string)
	}
	if len(payload) == 0 {
		delete(c.retainedTopics, topicPrefix)
		return
	}
	var topics []string
	if err := json.Unmarshal(payload, &topics); err != nil {
		slog.Debug("mqtt: malformed retained_topics manifest, ignored",
			"topic_prefix", topicPrefix, "err", err)
		return
	}
	c.retainedTopics[topicPrefix] = topics
}

// GetRetainedManifest returns a snapshot of the cached retained-topics
// manifest for the given device topic prefix, or nil if none has been seen
// in this app session. Caller owns the returned slice (defensive copy).
// in: topic prefix. out: list of topics or nil.
func (c *Client) GetRetainedManifest(topicPrefix string) []string {
	c.manifestMu.RLock()
	defer c.manifestMu.RUnlock()
	src, ok := c.retainedTopics[topicPrefix]
	if !ok {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

// ClearDeviceRetained issues an empty retained publish on every topic in
// the device's manifest, which deletes the broker-side retained message.
// Used by the device-delete cascade. Best-effort - per-
// topic publish failures are logged and counted but do not abort the sweep,
// since residual retained messages are operator-recoverable via mosquitto
// tools and a single ACL-rejected topic should not strand the rest.
//
// Returns the number of topics cleared, the number that failed, and any
// fatal error (currently only "no manifest cached"). The cache entry is
// dropped on success so a later list does not surface ghost topics.
// in: ctx (timeout for the broker round-trips), topicPrefix.
// out: cleared count, failed count, fatal err.
func (c *Client) ClearDeviceRetained(ctx context.Context, topicPrefix string) (cleared, failed int, err error) {
	topics := c.GetRetainedManifest(topicPrefix)
	if topics == nil {
		return 0, 0, fmt.Errorf("no retained-topics manifest cached for %q (device may have never published it, or app started after the device went offline)", topicPrefix)
	}
	for _, t := range topics {
		if err := ctx.Err(); err != nil {
			return cleared, failed, err
		}
		// Empty retained payload deletes the broker-side retained record per
		// MQTT 3.1.1 section 3.3.1.5. QoS 0 is fine - if the broker doesn't
		// see this publish the retained record outlives the device, which
		// the operator can clean up out of band.
		if perr := c.PublishRaw(t, []byte{}, 0, true); perr != nil {
			slog.Warn("mqtt: clear retained failed",
				"topic", t, "topic_prefix", topicPrefix, "err", perr)
			failed++
			continue
		}
		cleared++
	}
	c.manifestMu.Lock()
	delete(c.retainedTopics, topicPrefix)
	c.manifestMu.Unlock()
	return cleared, failed, nil
}

// onMessage is the single dispatch point for every inbound MQTT message.
// Retained flag is forwarded to handlers so they can suppress last_seen_at
// bumps on broker replays at app reconnect (a retained message is the last
// snapshot the broker has, not live activity).
// in: paho client (unused), message. out: none. Topic shape: <root>/<tenant>/<device>/{status,alert,sensor/<name>,info}.
func (c *Client) onMessage(_ mqttlib.Client, msg mqttlib.Message) {
	// paho dispatches each message on its own goroutine; an unhandled panic in
	// any handler below would otherwise crash the whole process. Recover at the
	// single dispatch point so one malformed message can't take the app down.
	defer func() {
		if rec := recover(); rec != nil {
			slog.Error("mqtt.callback_panic", "topic", msg.Topic(), "panic", rec)
		}
	}()

	// Fan out to every /admin/mqtt shell tap before ingest-side parsing so
	// raw binary payloads and unknown-tenant topics still land in the shell.
	// Taps are required to be non-blocking.
	c.fanoutTaps(msg.Topic(), msg.Payload(), msg.Retained(), msg.Qos())

	tenant, device, kind, sub, topicPrefix, ok := parseTopic(msg.Topic())
	if !ok {
		return
	}
	// Drop messages whose tenant slug isn't a known tenant. Legacy 3-tier
	// topics always parse to tenant="default" which is guaranteed to exist
	// (seeded by migration 0001), so this only rejects forged or stale
	// 4-tier prefixes from devices claiming a tenant that has been deleted.
	if !c.services.Tenants.ExistsBySlug(tenant) {
		slog.Debug("mqtt: unknown tenant slug, dropping", "tenant", tenant, "topic", msg.Topic())
		return
	}
	// Cross-tenant pairing check: when a device_id is already paired (active
	// non-revoked certificate) under a different tenant, the topic-claimed
	// tenant cannot be trusted - broker ACL drift would otherwise let the
	// app auto-create a duplicate device row in the wrong tenant. Drop the
	// message entirely so neither the tombstone path nor the handlers
	// observe it. A device with no active pairing (never paired, or last
	// pairing revoked) falls through; the topic tenant is authoritative.
	if pairedTenant, paired, err := c.services.Certificates.FindActivePairingTenant(context.Background(), device); err != nil {
		slog.Warn("mqtt: pairing lookup failed, dropping conservatively",
			"device", device, "topic", msg.Topic(), "err", err)
		return
	} else if paired && pairedTenant != tenant {
		slog.Error("mqtt: topic tenant does not match paired tenant - dropping",
			"device", device, "topic_tenant", tenant, "paired_tenant", pairedTenant,
			"topic", msg.Topic())
		return
	}
	retained := msg.Retained()
	// Tombstone gate. Retained replays of a deleted device
	// are cleared at the broker (empty-retained publish on the offending
	// topic) and then dropped so the auto-discovery path does not recreate
	// the device row. Live (non-retained) traffic from the same id is
	// allowed through: that path covers reflashed / re-paired hardware and
	// also clears the tombstone in handleStatus/handleInfo so the operator
	// does not have to chase it manually.
	tomb, terr := c.services.Devices.IsTombstoned(context.Background(), tenant, device)
	if terr != nil {
		slog.Warn("mqtt: tombstone lookup failed",
			"tenant", tenant, "device", device, "err", terr)
	} else if tomb {
		if retained {
			if perr := c.PublishRaw(msg.Topic(), []byte{}, 0, true); perr != nil {
				slog.Warn("mqtt: tombstone clear retained failed",
					"topic", msg.Topic(), "err", perr)
			} else {
				slog.Info("mqtt: cleared retained from tombstoned device",
					"tenant", tenant, "device", device, "topic", msg.Topic())
			}
			return
		}
		// Live traffic: drop the tombstone so the upsert path below can
		// recreate the row. Removal failure is non-fatal; the worst case
		// is one more retained sweep before the gate releases.
		if rerr := c.services.Devices.RemoveTombstone(context.Background(), tenant, device); rerr != nil {
			slog.Warn("mqtt: tombstone remove failed",
				"tenant", tenant, "device", device, "err", rerr)
		} else {
			slog.Info("mqtt: tombstone cleared by live traffic",
				"tenant", tenant, "device", device, "topic", msg.Topic())
		}
	}
	switch kind {
	case "status":
		if sub == "" {
			c.handleStatus(tenant, device, topicPrefix, msg.Payload(), retained)
		}
	case "info":
		if sub == "" {
			c.handleInfo(tenant, device, topicPrefix, msg.Payload(), retained)
		} else if sub == "retained_topics" && retained {
			c.cacheRetainedManifest(topicPrefix, msg.Payload())
		}
	case "alert":
		// Only route exact <prefix>/alert. Sub-paths like /alert/status are
		// device-side delivery meta (e.g. telegram-retry status from rules.lua)
		// and must not be ingested as alerts.
		if sub == "" {
			c.handleAlert(tenant, device, msg.Payload(), retained)
		}
	case "sensor":
		if sub != "" {
			c.handleSensor(tenant, device, sub, msg.Payload(), retained)
		}
	}
}

// parseTopic splits an MQTT topic into tenant, device, kind, sub.
// Supports two shapes:
//   - 4-tier: thesada/<tenant>/<device>/<kind>[/<sub-path>]
//   - 3-tier legacy: thesada/<device>/<kind>[/<sub-path>] (tenant defaulted to "default")
//
// Legacy is detected when parts[2] is a known kind ("status"/"alert"/"sensor").
// sub-path is joined with "/" so multi-level sensor metrics survive (e.g. "current/house_pump").
// in: full topic string. out: tenant, device, kind, sub (may be ""), ok=false if too short or unknown kind.
func parseTopic(topic string) (tenant, device, kind, sub, topicPrefix string, ok bool) {
	parts := strings.Split(topic, "/")
	if len(parts) < 3 {
		return "", "", "", "", "", false
	}
	isKind := func(s string) bool {
		return s == "status" || s == "alert" || s == "sensor" || s == "info"
	}
	// Legacy 3-tier: thesada/<device>/<kind>[/<sub>]
	if len(parts) >= 3 && isKind(parts[2]) {
		tenant = "default"
		device = parts[1]
		kind = parts[2]
		topicPrefix = parts[0] + "/" + parts[1]
		if len(parts) > 3 {
			sub = strings.Join(parts[3:], "/")
		}
		return tenant, device, kind, sub, topicPrefix, true
	}
	// 4-tier: thesada/<tenant>/<device>/<kind>[/<sub>]
	if len(parts) >= 4 && isKind(parts[3]) {
		tenant = parts[1]
		device = parts[2]
		kind = parts[3]
		topicPrefix = parts[0] + "/" + parts[1] + "/" + parts[2]
		if len(parts) > 4 {
			sub = strings.Join(parts[4:], "/")
		}
		return tenant, device, kind, sub, topicPrefix, true
	}
	return "", "", "", "", "", false
}

// handleStatus persists a heartbeat from a thesada/<tenant>/<device>/status message.
// Tolerates two payload shapes:
//   - JSON object with firmware_version/rssi/heap_free/uptime_s/hardware_type fields (full heartbeat)
//   - bare string "online"/"offline" presence
//
// last_seen_at is only bumped on a non-retained "online" presence (live event).
// "offline" never bumps - "I'm gone" is not "I was just here". Retained replays
// at app reconnect never bump either.
// in: tenant id, device id, raw payload, retained flag. out: none.
func (c *Client) handleStatus(tenant, device, topicPrefix string, payload []byte, retained bool) {
	trimmed := strings.TrimSpace(string(payload))
	if trimmed == "online" || trimmed == "offline" || trimmed == `"online"` || trimmed == `"offline"` {
		state := strings.Trim(trimmed, `"`)
		// Presence-only: update existing device row. Do NOT create on bare
		// online/offline - ESPHome and other non-thesada clients publish
		// status too, and we only want thesada-fw devices (which always
		// publish an info payload with firmware_version) in the db.
		if state == "online" && !retained {
			if _, found, err := c.services.Devices.BumpSeenIfExists(tenant, device); err != nil {
				slog.Error("presence bump failed", "tenant", tenant, "device", device, "err", err)
				return
			} else if !found {
				slog.Debug("presence for unknown device ignored (no info published)",
					"tenant", tenant, "device", device)
				return
			}
		}
		// Retained replays + "offline" never bump; we also don't create rows
		// for them. If the device doesn't exist, we have nothing to do.
		c.hub.Publish(tenant, device, map[string]string{"type": "presence", "device": device, "state": state})
		return
	}

	var status map[string]interface{}
	if err := json.Unmarshal(payload, &status); err != nil {
		slog.Error("status parse failed", "tenant", tenant, "device", device, "err", err)
		return
	}

	fwVersion, _ := status["firmware_version"].(string)
	hardwareType, _ := status["hardware_type"].(string)

	devicePk, err := c.upsertDevice(tenant, device, "", fwVersion, hardwareType, topicPrefix, retained)
	if err != nil {
		slog.Error("device upsert failed", "tenant", tenant, "device", device, "err", err)
		return
	}

	c.hub.Publish(tenant, device, map[string]string{"type": "status", "device": device})
	slog.Debug("status processed", "tenant", tenant, "device", device, "device_pk", devicePk)
}

// upsertDevice picks the live (Upsert) or no-bump (UpsertSeen) variant of
// the device upsert based on the retained flag of the source MQTT message.
// Retained messages are broker replays at subscriber reconnect, not live
// activity, so they must not advance last_seen_at.
// in: tenant_id, device_id, display_name, firmware_version, hardware_type, retained.
// out: device pk, error.
func (c *Client) upsertDevice(tenant, device, displayName, fwVersion, hardwareType, topicPrefix string, retained bool) (uuid.UUID, error) {
	if retained {
		return c.services.Devices.UpsertSeen(tenant, device, displayName, fwVersion, hardwareType, topicPrefix)
	}
	return c.services.Devices.Upsert(tenant, device, displayName, fwVersion, hardwareType, topicPrefix)
}

// handleAlert persists a device alert and triggers the notifier fan-out.
// Accepts only full-shape JSON alerts with a valid severity. Messages that
// are plain-text or missing fields are dropped at warn level - this is a
// firmware contract mismatch, not a user-visible problem, so it should not
// pollute device_alerts with half-formed rows that fail the db CHECK.
// in: tenant id, device id, raw JSON payload, retained flag. out: none (logs on error).
func (c *Client) handleAlert(tenant, device string, payload []byte, retained bool) {
	var alert map[string]interface{}
	if err := json.Unmarshal(payload, &alert); err != nil {
		slog.Warn("alert parse failed (non-JSON payload - firmware contract mismatch)",
			"tenant", tenant, "device", device, "payload", string(payload), "err", err)
		return
	}

	severity, _ := alert["severity"].(string)
	code, _ := alert["code"].(string)
	message, _ := alert["message"].(string)

	// Severity must match the db CHECK constraint. Anything else is dropped
	// with a log line so the firmware author can fix the publisher.
	if severity != "info" && severity != "warn" && severity != "crit" {
		slog.Warn("alert dropped: bad or missing severity",
			"tenant", tenant, "device", device, "severity", severity,
			"payload", string(payload))
		return
	}

	devicePk, found, err := c.services.Devices.BumpSeenIfExists(tenant, device)
	if err != nil {
		slog.Error("alert: device bump failed", "tenant", tenant, "device", device, "err", err)
		return
	}
	if !found {
		slog.Debug("alert from unknown device ignored (no info published)",
			"tenant", tenant, "device", device)
		return
	}
	_ = retained

	alertID, err := c.services.Alerts.InsertAlert(context.Background(), tenant, devicePk, severity, code, message, payload)
	if err != nil {
		slog.Error("alert insert failed", "device_pk", devicePk, "err", err)
		return
	}

	c.hub.Publish(tenant, device, map[string]string{"type": "alert", "device": device, "alert_id": fmt.Sprintf("%d", alertID)})
	slog.Debug("alert processed", "tenant", tenant, "device", device, "device_pk", devicePk, "alert_id", alertID)

	if c.notifier != nil {
		go func() {
			if err := c.notifier.Dispatch(context.Background(), alertID); err != nil {
				slog.Error("alert dispatch failed", "alert_id", alertID, "err", err)
			}
		}()
	}
}

// handleSensor persists a single sensor reading from thesada/<tenant>/<device>/sensor/<metric>.
// Accepts either a bare JSON number or an object like {"value": 23.5, "unit": "C"}.
// in: tenant id, device id, metric name, raw payload, retained flag. out: none (logs on error).
func (c *Client) handleSensor(tenant, device, metric string, payload []byte, retained bool) {
	value, text, ok := parseSensorPayload(payload)
	if !ok {
		slog.Error("sensor parse failed", "tenant", tenant, "device", device, "metric", metric, "payload", string(payload))
		return
	}
	_ = retained

	devicePk, found, err := c.services.Devices.BumpSeenIfExists(tenant, device)
	if err != nil {
		slog.Error("sensor: device bump failed", "tenant", tenant, "device", device, "err", err)
		return
	}
	if !found {
		slog.Debug("sensor from unknown device ignored (no info published)",
			"tenant", tenant, "device", device, "metric", metric)
		return
	}

	_, err = c.services.Telemetry.RecordTelemetry(context.Background(), tenant, devicePk, metric, value, text, payload)
	if err != nil {
		slog.Error("telemetry insert failed", "device_pk", devicePk, "metric", metric, "err", err)
		return
	}

	c.hub.Publish(tenant, device, map[string]string{"type": "sensor", "device": device, "metric": metric})
	slog.Debug("sensor processed", "tenant", tenant, "device", device, "device_pk", devicePk, "metric", metric)
}

// handleInfo persists device metadata from a retained thesada/<tenant>/<device>/info
// payload. The firmware publishes this once per successful MQTT reconnect with
// firmware_version, hardware_type, board, chip info, mac, psram, build_time.
// Fills the HARDWARE and FIRMWARE columns on /devices that the bare presence
// status path cannot populate.
// in: tenant id, device id, JSON payload, retained flag. out: none.
func (c *Client) handleInfo(tenant, device, topicPrefix string, payload []byte, retained bool) {
	var info map[string]interface{}
	if err := json.Unmarshal(payload, &info); err != nil {
		slog.Error("info parse failed", "tenant", tenant, "device", device, "err", err)
		return
	}
	fwVersion, _ := info["firmware_version"].(string)
	hardwareType, _ := info["hardware_type"].(string)
	devicePk, err := c.upsertDevice(tenant, device, "", fwVersion, hardwareType, topicPrefix, retained)
	if err != nil {
		slog.Error("device upsert failed", "tenant", tenant, "device", device, "err", err)
		return
	}
	c.hub.Publish(tenant, device, map[string]string{"type": "info", "device": device})
	slog.Debug("info processed", "tenant", tenant, "device", device, "fw", fwVersion, "hw", hardwareType)

	// Drift detection: compare device-reported hashes to latest snapshots.
	// If a hash differs (or no snapshot exists), pull the file in a goroutine.
	hashMap := map[string]string{
		"config.json":        "",
		"/scripts/main.lua":  "",
		"/scripts/rules.lua": "",
	}
	if h, ok := info["config_hash"].(string); ok {
		hashMap["config.json"] = h
	}
	if h, ok := info["scripts_main_hash"].(string); ok {
		hashMap["/scripts/main.lua"] = h
	}
	if h, ok := info["scripts_rules_hash"].(string); ok {
		hashMap["/scripts/rules.lua"] = h
	}

	// Collect paths that need pulling, then process sequentially in one
	// goroutine. Running concurrent CLIRequests against the same device
	// causes response cross-contamination (all taps match cli/response).
	var driftPaths []string
	for path, deviceHash := range hashMap {
		if deviceHash == "" {
			continue
		}
		storedHash, _ := c.services.DeviceFiles.LatestSHA(context.Background(), tenant, devicePk, path)
		if storedHash == deviceHash {
			continue
		}
		slog.Info("config drift detected", "device", device, "path", path,
			"stored", storedHash, "device_hash", deviceHash)
		driftPaths = append(driftPaths, path)
	}
	if len(driftPaths) > 0 {
		go func() {
			for _, p := range driftPaths {
				c.pullAndSnapshot(tenant, devicePk, topicPrefix, p, "drift", hashMap[p])
			}
			// Discover additional scripts not covered by firmware hashes.
			// fs.ls /scripts returns lines like "  3858  alerts.lua".
			c.discoverAndSnapshotScripts(tenant, devicePk, topicPrefix)
		}()
	}
}

// discoverAndSnapshotScripts lists /scripts/ on the device and snapshots
// any .lua files that don't have a stored snapshot yet. Catches custom
// scripts beyond main.lua and rules.lua.
// in: tenant id, device pk, topic prefix. out: none.
func (c *Client) discoverAndSnapshotScripts(tenant string, devicePk uuid.UUID, topicPrefix string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := c.CLIRequest(ctx, topicPrefix, "fs.ls", "/scripts")
	if err != nil || !resp.OK {
		return
	}

	for _, line := range resp.Output {
		// Parse "  3858  /scripts/rules.lua" format. Firmware v1.3.9+ emits
		// absolute paths from fs.ls; older firmware emitted bare basenames.
		line = strings.TrimSpace(line)
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		name := parts[1]
		if !strings.HasSuffix(name, ".lua") {
			continue
		}
		path := name
		if !strings.HasPrefix(path, "/") {
			path = "/scripts/" + name
		}

		// Skip if we already have a canonical row (from hash-based drift or earlier)
		existing, _ := c.services.DeviceFiles.Latest(context.Background(), tenant, devicePk, path)
		if existing != nil {
			continue
		}

		slog.Info("discovered untracked script", "device_pk", devicePk, "path", path)
		// Empty expectedSha: discovery has no device-reported hash to verify
		// against. Content shape is still validated inside pullAndSnapshot.
		c.pullAndSnapshot(tenant, devicePk, topicPrefix, path, "drift", "")
	}
}

// pullAndSnapshot reads a file from a device via MQTT CLI and stores it as
// a config snapshot. For config.json uses config.dump, for scripts uses
// chunked fs.cat. Runs in a goroutine - non-blocking.
//
// Validates content shape before persisting:
//   - config.json must parse as a JSON object (not garbage shell output).
//   - script files must be non-empty and not look like shell errors.
//   - if expectedSha is non-empty, the local sha of received content must
//     match the device-reported hash that triggered the pull. Mismatch =
//     captured someone else's response in the CLI window; abort.
//
// in: tenant id, device pk, topic prefix, file path, source label, expected
// sha (empty string when caller has no reference hash). out: none.
func (c *Client) pullAndSnapshot(tenant string, devicePk uuid.UUID, topicPrefix, path, source, expectedSha string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var content string
	if path == "config.json" {
		resp, err := c.CLIRequest(ctx, topicPrefix, "config.dump", "")
		if err != nil {
			slog.Error("drift pull failed", "path", path, "err", err)
			return
		}
		if !resp.OK {
			slog.Error("drift pull device error", "path", path, "output", resp.Output)
			return
		}
		content = strings.Join(resp.Output, "\n")
	} else {
		// Chunked read for script files
		var buf strings.Builder
		offset := 0
		for {
			payload := fmt.Sprintf("%s %d 2048", path, offset)
			resp, err := c.CLIRequest(ctx, topicPrefix, "fs.cat", payload)
			if err != nil {
				slog.Error("drift pull chunk failed", "path", path, "offset", offset, "err", err)
				return
			}
			if !resp.OK {
				slog.Error("drift pull chunk device error", "path", path, "output", resp.Output)
				return
			}
			if resp.Data != nil {
				buf.WriteString(*resp.Data)
			}
			if resp.Done != nil && *resp.Done {
				break
			}
			if resp.Length != nil {
				offset += *resp.Length
			} else {
				break
			}
		}
		content = buf.String()
	}

	if !validSnapshotContent(path, content) {
		slog.Warn("drift pull content failed validation - not stored",
			"path", path, "bytes", len(content),
			"head", truncForLog(content, 80))
		return
	}

	h := sha256.Sum256([]byte(content))
	hashHex := hex.EncodeToString(h[:])

	if expectedSha != "" && hashHex != expectedSha {
		slog.Warn("drift pull sha mismatch - not stored",
			"path", path, "expected", expectedSha, "got", hashHex)
		return
	}

	if err := c.services.DeviceFiles.Upsert(context.Background(), tenant, devicePk, path, content, hashHex, source, nil); err != nil {
		slog.Error("drift file upsert failed", "path", path, "err", err)
	} else {
		slog.Info("device_file saved", "path", path, "source", source, "sha256", hashHex[:12])
	}
}

// validSnapshotContent rejects obvious garbage before it lands in
// device_files / device_file_history. Drift pulls fire `config.dump` / chunked
// `fs.cat` and join the device's response output; if an unrelated CLI
// response (ota.check ack, log spam, fs.ls output) lands in the same
// window, content holds shell text that is not the file at `path`. The
// shell-output rows came from exactly that race.
//
// in: path - the LittleFS path the snapshot is for; content - bytes read.
// out: true if shape matches expectations for the given path.
func validSnapshotContent(path, content string) bool {
	if path == "config.json" {
		// Must be a JSON object. json.Valid alone would accept "true" or
		// a bare number; require the object form to match the firmware's
		// config.dump output.
		trimmed := strings.TrimSpace(content)
		if !strings.HasPrefix(trimmed, "{") || !strings.HasSuffix(trimmed, "}") {
			return false
		}
		var probe map[string]interface{}
		return json.Unmarshal([]byte(trimmed), &probe) == nil
	}
	if strings.HasSuffix(path, ".lua") {
		if len(strings.TrimSpace(content)) == 0 {
			return false
		}
		// Reject obvious shell error markers slipping in instead of script
		// bytes. These would not appear in legitimate Lua.
		head := content
		if len(head) > 200 {
			head = head[:200]
		}
		for _, marker := range []string{"Usage:", "Error:", "Failed to", "Unknown command:"} {
			if strings.Contains(head, marker) {
				return false
			}
		}
		return true
	}
	// Unknown path shape - default to permissive so future file types do
	// not silently get dropped without a code update.
	return true
}

// truncForLog returns at most n bytes of s for slog values. Avoids
// blowing up structured logs when a 10 KB Lua file fails validation.
// in: s, n. out: truncated string.
func truncForLog(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// parseSensorPayload accepts bare number, bare JSON string, JSON object with
// "value"/"text" keys, or an unquoted raw string (legacy firmware sends
// "Discharging", "On", "Off" without JSON quoting). Numeric value is only
// returned when the payload truly parsed as a number; pure-text payloads get
// a nil *float64 so the caller can store a NULL value_num column.
// in: raw MQTT payload. out: *numeric value (nil if not numeric), text value, parsed-ok flag.
func parseSensorPayload(payload []byte) (*float64, string, bool) {
	var num float64
	if err := json.Unmarshal(payload, &num); err == nil {
		return &num, "", true
	}
	var str string
	if err := json.Unmarshal(payload, &str); err == nil {
		return nil, str, true
	}
	var obj map[string]interface{}
	if err := json.Unmarshal(payload, &obj); err == nil {
		var val *float64
		if v, ok := obj["value"].(float64); ok {
			val = &v
		}
		text, _ := obj["text"].(string)
		return val, text, true
	}
	trimmed := strings.TrimSpace(string(payload))
	if trimmed == "" {
		return nil, "", false
	}
	return nil, trimmed, true
}
