// Device config and script management. Super-admin only.
// Reads/writes device files and config via MQTT CLI commands, using the
// chunked fs.cat/fs.write/fs.append protocol.
//
// CLI commands and chunked writes run async: the POST
// endpoints enqueue a request, kick off a goroutine that handles the MQTT
// round-trip up to cfg.CLIRequestTimeout, and return a request_id. The
// frontend polls GET /admin/devices/{id}/config/cmd/result?id=... until
// the store returns a terminal status. Lets cellular-attached devices (RTT
// often >10s mid-backoff) finish without tripping HTTP / proxy timeouts.
package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/service"
)

// deviceTopicPrefix returns the MQTT topic prefix for a device. Uses the
// stored mqtt_topic_prefix if available, otherwise falls back to the
// constructed root/tenant/device path.
// in: device. out: topic prefix string.
func (s *Server) deviceTopicPrefix(device *service.Device) string {
	if device.MQTTTopicPrefix != nil && *device.MQTTTopicPrefix != "" {
		return *device.MQTTTopicPrefix
	}
	return s.cfg.MQTTTopicRoot + "/" + device.TenantID + "/" + device.DeviceID
}

// handleAdminDeviceConfig renders the device config management page.
// Shows config editor, script manager, and file browser for one device.
// in: writer, request (with {id} path param). out: HTML page.
func (s *Server) handleAdminDeviceConfig(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil {
		// A real backend error must not masquerade as 404 (AGENTS.md: fail loud).
		slog.Error("device lookup failed", "device", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}

	topicPrefix := s.deviceTopicPrefix(device)

	// Pre-fill the editor with the most recent config.json snapshot from
	// device_files so the textarea is never empty on page load. Operators
	// hitting a cellular-attached device can read the last-known config
	// immediately instead of staring at a blank box while the async
	// `Load from device` poll runs (potentially up to 120s). Snapshot may
	// be stale; saveConfig still requires a fresh `Load from device`
	// before it will diff (originalConfig stays null until live load).
	//
	var lastSnapshot map[string]interface{}
	if snap, ferr := s.services.DeviceFiles.Latest(r.Context(), device.TenantID, device.ID, "config.json"); ferr == nil && snap != nil {
		lastSnapshot = map[string]interface{}{
			"Content":   snap.Content,
			"UpdatedAt": snap.UpdatedAt,
			"Source":    snap.Source,
		}
	}

	s.render(w, r, "admin-device-config.html", map[string]interface{}{
		"Device":            device,
		"TopicPrefix":       topicPrefix,
		"CLITimeoutSeconds": int(s.cfg.CLIRequestTimeout.Seconds()),
		"LastSnapshot":      lastSnapshot,
	})
}

// cliCmdRequest is the JSON body for the /admin/devices/{id}/config/cmd endpoint.
type cliCmdRequest struct {
	Command string `json:"command"`
	Payload string `json:"payload"`
}

// cliEnqueueResponse is returned by enqueue endpoints. RequestID is the key
// the frontend polls /result with. TimeoutSeconds is the server-side budget
// so the poll loop knows when to give up.
type cliEnqueueResponse struct {
	RequestID      string `json:"request_id"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// handleAdminDeviceConfigCmd enqueues an async CLI request. The MQTT round-
// trip happens in a goroutine bounded by cfg.CLIRequestTimeout; the response
// (or timeout / error) lands in s.cliRequests for the result endpoint to
// pick up. Frontend JS polls /result?id=... every couple of seconds.
// in: writer, request (JSON body with command + payload). out: JSON enqueue ack.
func (s *Server) handleAdminDeviceConfigCmd(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "bad device id", http.StatusBadRequest)
		return
	}

	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil {
		// A real backend error must not masquerade as 404 (AGENTS.md: fail loud).
		slog.Error("device lookup failed", "device", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}

	var req cliCmdRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	if req.Command == "" {
		http.Error(w, "command required", http.StatusBadRequest)
		return
	}

	topicPrefix := s.deviceTopicPrefix(device)
	user := authmw.CurrentUser(r)
	slog.Info("admin config cmd enqueue",
		"user", user.Email, "device", device.DeviceID,
		"cmd", req.Command, "payload_len", len(req.Payload))

	reqID := s.cliRequests.enqueue()

	// Goroutine context is detached from r.Context() via WithoutCancel - the
	// HTTP request returns immediately and the browser drops r.Context() on
	// its way out, but the proxy must keep running (bounded by
	// cfg.CLIRequestTimeout, applied inside runCLICmd). WithoutCancel keeps
	// the request's context values while shedding its cancellation.
	go s.runCLICmd(context.WithoutCancel(r.Context()), reqID, device, topicPrefix, req.Command, req.Payload, &user.ID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cliEnqueueResponse{
		RequestID:      reqID.String(),
		TimeoutSeconds: int(s.cfg.CLIRequestTimeout.Seconds()),
	})
}

// runCLICmd is the goroutine body for an enqueued CLI request. Bounded by
// cfg.CLIRequestTimeout. On success it also fires the snapshot-on-read path
// that the synchronous handler used to run inline.
// in: request id, device, topic prefix, command, payload, user id. out: none (writes to store).
// parentCtx is a request-derived but non-cancellable context
// (context.WithoutCancel) - the async CLI proxy outlives the HTTP request
// so it must not inherit r.Context() cancellation, but it should keep the
// request's values (trace/correlation IDs) and is the base for the
// CLIRequestTimeout deadline below.
func (s *Server) runCLICmd(parentCtx context.Context, reqID uuid.UUID, device *service.Device, topicPrefix, command, payload string, userID *uuid.UUID) {
	ctx, cancel := context.WithTimeout(parentCtx, s.cfg.CLIRequestTimeout)
	defer cancel()

	resp, err := s.mqtt.CLIRequest(ctx, topicPrefix, command, payload)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			s.cliRequests.markError(reqID, cliStatusTimeout,
				fmt.Sprintf("device did not respond within %s", s.cfg.CLIRequestTimeout))
		} else {
			s.cliRequests.markError(reqID, cliStatusError, err.Error())
		}
		return
	}
	s.cliRequests.markDone(reqID, resp)

	if resp.OK {
		s.snapshotFromCmdResponse(ctx, device.TenantID, device.ID, command, payload, resp, userID)
	}
}

// handleAdminDeviceConfigCmdResult returns the terminal status of an
// enqueued CLI request, or {status:"pending"} if it has not finished yet.
// Terminal entries are dropped on read - one successful poll, then gone.
// in: writer, request (with ?id= query). out: JSON result envelope.
func (s *Server) handleAdminDeviceConfigCmdResult(w http.ResponseWriter, r *http.Request) {
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	entry := s.cliRequests.get(id)
	w.Header().Set("Content-Type", "application/json")
	if entry == nil {
		// Either never existed, already consumed, or pruned by TTL. Treat
		// as terminal-unknown so the frontend stops polling.
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"status": "expired",
			"error":  "request id not found (expired or already read)",
		})
		return
	}

	out := map[string]interface{}{"status": string(entry.Status)}
	if entry.Response != nil {
		out["response"] = entry.Response
	}
	if entry.ErrorMsg != "" {
		out["error"] = entry.ErrorMsg
	}
	_ = json.NewEncoder(w).Encode(out)
}

// snapshotFromCmdResponse saves a config snapshot if the CLI command was a
// config.dump or a chunked fs.cat read. Non-blocking (runs in goroutine).
// in: device pk, command, payload, response, user id. out: none.
func (s *Server) snapshotFromCmdResponse(ctx context.Context, tenantID string, devicePk uuid.UUID, command, payload string, resp *mqtt.CLIResponse, userID *uuid.UUID) {
	var path, content string
	switch command {
	case "config.dump":
		path = "config.json"
		content = joinOutput(resp.Output)
	case "fs.cat":
		// Only snapshot complete reads (done=true with offset 0 won't happen
		// from chunked reads - the frontend assembles. Skip partial chunks.)
		return
	default:
		return
	}
	if content == "" {
		return
	}
	h := sha256.Sum256([]byte(content))
	hashHex := hex.EncodeToString(h[:])
	if err := s.services.DeviceFiles.Upsert(ctx, tenantID, devicePk, path, content, hashHex, "read", userID); err != nil {
		slog.Error("device_file upsert failed", "path", path, "err", err)
	}
}

func joinOutput(lines []string) string {
	result := ""
	for i, l := range lines {
		if i > 0 {
			result += "\n"
		}
		result += l
	}
	return result
}

// cliWriteRequest is the JSON body for the /admin/devices/{id}/config/write endpoint.
type cliWriteRequest struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// handleAdminDeviceConfigWrite enqueues a chunked async file write. The
// goroutine runs the full fs.write + fs.append chain bounded by
// cfg.CLIRequestTimeout per chunk; final summary lands in the store as a
// synthetic CLIResponse with output lines "<bytes> bytes in <n> chunk(s)".
// in: writer, request (JSON body with path + content). out: JSON enqueue ack.
func (s *Server) handleAdminDeviceConfigWrite(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "bad device id", http.StatusBadRequest)
		return
	}

	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil {
		// A real backend error must not masquerade as 404 (AGENTS.md: fail loud).
		slog.Error("device lookup failed", "device", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}

	var req cliWriteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	if req.Path == "" || req.Content == "" {
		http.Error(w, "path and content required", http.StatusBadRequest)
		return
	}

	topicPrefix := s.deviceTopicPrefix(device)
	user := authmw.CurrentUser(r)
	slog.Info("admin config write enqueue",
		"user", user.Email, "device", device.DeviceID,
		"path", req.Path, "content_len", len(req.Content))

	reqID := s.cliRequests.enqueue()
	// Detached goroutine - same rationale as runCLICmd above: the async CLI
	// proxy outlives the HTTP request, so WithoutCancel sheds r.Context()
	// cancellation while keeping its values; runCLIWrite applies the
	// CLIRequestTimeout deadline per chunk.
	go s.runCLIWrite(context.WithoutCancel(r.Context()), reqID, device, topicPrefix, req.Path, req.Content, &user.ID)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cliEnqueueResponse{
		RequestID:      reqID.String(),
		TimeoutSeconds: int(s.cfg.CLIRequestTimeout.Seconds()),
	})
}

// runCLIWrite is the goroutine body for an enqueued chunked write. Each
// chunk is bounded by cfg.CLIRequestTimeout independently. On any chunk
// failure the entry is marked error and the chain stops. On success the
// snapshot row is upserted and the entry is marked done with a summary.
// in: request id, device, topic prefix, path, content, user id. out: none (writes to store).
// parentCtx: request-derived non-cancellable context (see runCLICmd).
func (s *Server) runCLIWrite(parentCtx context.Context, reqID uuid.UUID, device *service.Device, topicPrefix, path, content string, userID *uuid.UUID) {
	// Chunk size: leave room for path + newline in the MQTT payload.
	// Device buffer_in is typically 4096; path overhead ~64 bytes max.
	const chunkSize = 3900

	contentBytes := []byte(content)
	totalChunks := (len(contentBytes) + chunkSize - 1) / chunkSize

	for i := 0; i < totalChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > len(contentBytes) {
			end = len(contentBytes)
		}
		chunk := contentBytes[start:end]

		cmd := "fs.write"
		if i > 0 {
			cmd = "fs.append"
		}

		payload := make([]byte, 0, len(path)+1+len(chunk))
		payload = append(payload, []byte(path)...)
		payload = append(payload, '\n')
		payload = append(payload, chunk...)

		ctx, cancel := context.WithTimeout(parentCtx, s.cfg.CLIRequestTimeout)
		resp, err := s.mqtt.CLIRequestRaw(ctx, topicPrefix, cmd, payload)
		cancel()

		if err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				s.cliRequests.markError(reqID, cliStatusTimeout,
					fmt.Sprintf("chunk %d/%d timed out after %s", i+1, totalChunks, s.cfg.CLIRequestTimeout))
			} else {
				s.cliRequests.markError(reqID, cliStatusError,
					fmt.Sprintf("chunk %d/%d failed: %v", i+1, totalChunks, err))
			}
			return
		}
		if !resp.OK {
			s.cliRequests.markError(reqID, cliStatusError,
				fmt.Sprintf("chunk %d/%d device error: %v", i+1, totalChunks, resp.Output))
			return
		}
	}

	h := sha256.Sum256(contentBytes)
	hashHex := hex.EncodeToString(h[:])
	if err := s.services.DeviceFiles.Upsert(parentCtx, device.TenantID, device.ID, path, content, hashHex, "write", userID); err != nil {
		slog.Error("write device_file upsert failed", "path", path, "err", err)
	}

	s.cliRequests.markDone(reqID, &mqtt.CLIResponse{
		Cmd: "fs.write",
		OK:  true,
		Output: []string{
			fmt.Sprintf("%d bytes in %d chunk(s)", len(contentBytes), totalChunks),
		},
	})
}

// cliSnapshotRequest is the JSON body for the /admin/devices/{id}/config/snapshot endpoint.
type cliSnapshotRequest struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Source  string `json:"source"`
}

// handleAdminDeviceConfigSnapshot upserts a device_files row from content the
// frontend assembled out of a chunked fs.cat read. The single-shot config.dump
// path used to do this implicitly via snapshotFromCmdResponse, but on cellular
// the single-shot publish overflows the SIM7080 AT-bus line buffer when the
// config JSON gets large. Chunked fs.cat /config.json works around that and
// this endpoint records the final assembled content as the canonical snapshot.
//
//	follow-up.
//
// in: writer, request (JSON body with path + content + source). out: JSON ok.
func (s *Server) handleAdminDeviceConfigSnapshot(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "bad device id", http.StatusBadRequest)
		return
	}
	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil {
		// A real backend error must not masquerade as 404 (AGENTS.md: fail loud).
		slog.Error("device lookup failed", "device", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}
	var req cliSnapshotRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Path == "" || req.Content == "" {
		http.Error(w, "path and content required", http.StatusBadRequest)
		return
	}
	source := req.Source
	if source == "" {
		source = "read"
	}
	user := authmw.CurrentUser(r)
	h := sha256.Sum256([]byte(req.Content))
	hashHex := hex.EncodeToString(h[:])
	if err := s.services.DeviceFiles.Upsert(r.Context(), device.TenantID, device.ID, req.Path, req.Content, hashHex, source, &user.ID); err != nil {
		slog.Error("snapshot upsert failed",
			"user", user.Email, "device", device.DeviceID, "path", req.Path, "err", err)
		http.Error(w, "snapshot upsert failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "bytes": len(req.Content)})
}

// handleAdminDeviceConfigHistory returns the version history for a device+path
// as JSON. Used by the config page frontend to populate the history panel.
// in: writer, request (with {id} path param, ?path= query). out: JSON array.
func (s *Server) handleAdminDeviceConfigHistory(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "bad device id", http.StatusBadRequest)
		return
	}

	path := r.URL.Query().Get("path")
	if path == "" {
		http.Error(w, "path required", http.StatusBadRequest)
		return
	}

	// Resolve the device's tenant so HistoryPage can scope under RLS.
	// Super-admin handler - GetByIDAny is the cross-tenant lookup.
	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil {
		// A real backend error must not masquerade as 404 (AGENTS.md: fail loud).
		slog.Error("device lookup failed", "device", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}

	limit := parsePagingParam(r.URL.Query().Get("limit"), 50, 10, 250)
	offset := parsePagingParam(r.URL.Query().Get("offset"), 0, 0, 1_000_000)

	history, total, err := s.services.DeviceFiles.HistoryPage(r.Context(), device.TenantID, id, path, limit, offset)
	if err != nil {
		http.Error(w, "query failed", http.StatusInternalServerError)
		return
	}
	if history == nil {
		history = []service.DeviceFileHistory{}
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"snapshots": history,
		"total":     total,
		"limit":     limit,
		"offset":    offset,
	})
}

// parsePagingParam parses a single integer query param with a default,
// min, and max. Strings that don't parse fall back to the default; out-
// of-range values clamp. Used for ?limit= and ?offset= on the history
// endpoint and any other paged JSON list in this package.
// in: raw string, default, min, max. out: clamped integer.
func parsePagingParam(s string, def, lo, hi int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	if n < lo {
		return lo
	}
	if n > hi {
		return hi
	}
	return n
}
