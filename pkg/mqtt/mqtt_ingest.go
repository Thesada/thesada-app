package mqtt

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/uuid"
)

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
