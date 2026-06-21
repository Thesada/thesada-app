package mqtt

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
)

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
