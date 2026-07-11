// Package mqtt subscribes to thesada/+/+/# and writes heartbeats, telemetry,
// and alerts into Postgres. Single subscriber, single connection.
package mqtt

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	// Eclipse Paho MQTT Go client is dual-licensed EPL-2.0 / EDL-1.0. We
	// use it under the Eclipse Distribution License v1.0 (BSD-3-Clause
	// equivalent), which is compatible with this app's AGPL-3.0-only
	// licence. The selection is recorded in THIRD_PARTY_LICENSES at the
	// repo root.
	mqttlib "github.com/eclipse/paho.mqtt.golang"

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

	// Broker connectivity for logs + health endpoints. Own flag rather than
	// paho's IsConnected(), which reports true through the whole reconnect
	// window and would hide an outage from /readyz.
	connUp atomic.Bool

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

	// Connectivity edges are state_change events; without these a broker
	// outage was invisible (auto-reconnect recovers ingest, but nothing
	// logged the gap and /healthz stayed ok throughout).
	opts.SetConnectionLostHandler(func(_ mqttlib.Client, err error) {
		cli.connUp.Store(false)
		slog.Error("mqtt.connection.state_change", "from", "up", "to", "down", "err", err)
	})
	opts.SetReconnectingHandler(func(_ mqttlib.Client, _ *mqttlib.ClientOptions) {
		// Fires on every 5 s retry - keep per-attempt noise at debug; the
		// up/down edges above carry the signal.
		slog.Debug("mqtt.connection.reconnecting")
	})

	opts.OnConnect = func(c mqttlib.Client) {
		cli.connUp.Store(true)
		slog.Info("mqtt.connection.state_change", "from", "down", "to", "up")
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

// Status reports broker connectivity for the health endpoints.
// in: receiver. out: "disabled" (no broker configured), "up", or "down".
func (c *Client) Status() string {
	if c.c == nil {
		return "disabled"
	}
	if c.connUp.Load() {
		return "up"
	}
	return "down"
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
