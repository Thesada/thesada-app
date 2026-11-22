// Device config and script management. Super-admin only.
// Reads/writes device files and config via MQTT CLI commands, using the
// chunked fs.cat/fs.write/fs.append protocol. Writes stage to <path>.new and
// fs.mv it over the target once every chunk acked.
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
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/authz"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/safego"
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

	// A config change must not run beside a staged write that already passed the guard.
	claim := uuid.Nil
	if changesConfig(req.Command, req.Payload) {
		var ok bool
		claim, ok = s.claimDeviceWrite(device.ID, cmdClaimTTL(s.cfg.CLIRequestTimeout))
		if !ok {
			http.Error(w, "a write to this device is already running", http.StatusConflict)
			return
		}
	}

	topicPrefix := s.deviceTopicPrefix(device)
	user := authmw.CurrentUser(r)
	slog.Info("admin config cmd enqueue",
		"user", user.Email, "device", device.DeviceID,
		"cmd", req.Command, "payload_len", len(req.Payload))

	// Recorded at enqueue, before the device answers: a command that hangs
	// or reboots the device is still on the trail. Payload size only.
	s.audit(r.Context(), user, authz.DeviceCommand, service.AuditEntry{
		TargetType: "device", TargetID: device.ID.String(), TenantID: device.TenantID,
		Detail: map[string]any{"device_id": device.DeviceID, "command": req.Command, "payload_bytes": len(req.Payload)},
	})
	reqID := s.cliRequests.enqueue()

	// Goroutine context is detached from r.Context() via WithoutCancel - the
	// HTTP request returns immediately and the browser drops r.Context() on
	// its way out, but the proxy must keep running (bounded by
	// cfg.CLIRequestTimeout, applied inside runCLICmd). WithoutCancel keeps
	// the request's context values while shedding its cancellation.
	cliCtx := context.WithoutCancel(r.Context())
	s.goCLI(reqID, "web.cli_cmd", device.DeviceID, func() {
		s.runCLICmd(cliCtx, reqID, claim, device, topicPrefix, req.Command, req.Payload, &user.ID)
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cliEnqueueResponse{
		RequestID:      reqID.String(),
		TimeoutSeconds: int(s.cfg.CLIRequestTimeout.Seconds()),
	})
}

// goCLI runs an enqueued CLI request body on its own goroutine under guardCLI.
// in: request id, site name, device id, body. out: none.
func (s *Server) goCLI(reqID uuid.UUID, site, deviceID string, body func()) {
	go s.guardCLI(reqID, site, deviceID, body)
}

// guardCLI runs body and fails a still-pending request on a panic, or it
// would never be pruned. A request body already marked done stays done.
// in: request id, site name, device id, body. out: none.
func (s *Server) guardCLI(reqID uuid.UUID, site, deviceID string, body func()) {
	if safego.Run(site, body, "device", deviceID, "request_id", reqID) {
		s.cliRequests.failPending(reqID, "internal error, the cause is in the app log")
	}
}

// runCLICmd is the goroutine body for an enqueued CLI request. A config-changing command holds
// claim (uuid.Nil otherwise) and marks the config changed before and after it runs.
// in: request id, claim, device, topic prefix, command, payload, user id. out: none (writes to store).
// parentCtx is a request-derived but non-cancellable context
// (context.WithoutCancel) - the async CLI proxy outlives the HTTP request
// so it must not inherit r.Context() cancellation, but it should keep the
// request's values (trace/correlation IDs) and is the base for the
// CLIRequestTimeout deadline below.
func (s *Server) runCLICmd(parentCtx context.Context, reqID, claim uuid.UUID, device *service.Device, topicPrefix, command, payload string, userID *uuid.UUID) {
	changes := claim != uuid.Nil
	var prevChange *time.Time
	if changes {
		defer s.releaseDeviceWrite(device.ID, claim)
		if !s.renewDeviceWrite(device.ID, claim, cmdClaimTTL(s.cfg.CLIRequestTimeout)) {
			s.cliRequests.markError(reqID, reqStatusError, "another write took over this device, nothing was sent")
			return
		}
		// Reads already running turn stale. Without the mark the command is not sent.
		var err error
		if prevChange, err = s.markConfigChanging(parentCtx, device, cmdClaimTTL(s.cfg.CLIRequestTimeout)); err != nil {
			s.releaseDeviceWrite(device.ID, claim)
			s.cliRequests.markError(reqID, reqStatusError, "could not record the config change, nothing was sent")
			return
		}
	}
	var readStart time.Time
	if command == "config.dump" {
		start, err := s.readStart(parentCtx, device)
		if err != nil {
			s.cliRequests.markError(reqID, reqStatusError, "could not start the device read, nothing was sent")
			return
		}
		readStart = start
	}

	ctx, cancel := context.WithTimeout(parentCtx, s.cfg.CLIRequestTimeout)
	defer cancel()
	resp, err := s.mqtt.CLIRequest(ctx, topicPrefix, command, payload)
	if changes {
		// A read served while the command ran is stale too.
		if merr := s.endConfigChange(parentCtx, device, prevChange); merr != nil {
			slog.Error("mark config changed after a CLI command", "device", device.DeviceID, "err", merr)
		}
		// Released before the entry turns terminal, so a write posted on done is not a 409.
		s.releaseDeviceWrite(device.ID, claim)
	}
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			s.cliRequests.markError(reqID, reqStatusTimeout,
				fmt.Sprintf("device did not respond within %s", s.cfg.CLIRequestTimeout))
		} else {
			s.cliRequests.markError(reqID, reqStatusError, err.Error())
		}
		return
	}
	s.cliRequests.markDone(reqID, resp)

	// The box shows any reply. Only one that echoed the req_id is stored as a device read.
	if resp.OK && command == "config.dump" && !resp.Correlated {
		slog.Warn("config.dump reply without req_id, not stored", "device", device.DeviceID)
	}
	if resp.OK && command == "config.dump" && resp.Correlated {
		s.snapshotFromCmdResponse(parentCtx, device.TenantID, device.ID, resp, userID, readStart)
	}
}

// cmdClaimTTL outlasts one config-changing CLI command and its two change marks.
func cmdClaimTTL(step time.Duration) time.Duration {
	return step + 2*snapshotUpsertTimeout + time.Minute
}

// endConfigChange closes the window markConfigChanging opened, under its own deadline.
// in: parent ctx, device, the stamp that mark replaced. out: error.
func (s *Server) endConfigChange(parentCtx context.Context, device *service.Device, prev *time.Time) error {
	ctx, cancel := context.WithTimeout(parentCtx, snapshotUpsertTimeout)
	defer cancel()
	return s.services.DeviceFiles.EndConfigChange(ctx, device.TenantID, device.ID, prev)
}

// markConfigChanging records a config change that may land within window, the claim it runs
// under, under its own deadline. out: the stamp it replaced, for endConfigChange, error.
func (s *Server) markConfigChanging(parentCtx context.Context, device *service.Device, window time.Duration) (*time.Time, error) {
	ctx, cancel := context.WithTimeout(parentCtx, snapshotUpsertTimeout)
	defer cancel()
	return s.services.DeviceFiles.MarkConfigChanging(ctx, device.TenantID, device.ID, window)
}

// readStart is DeviceFiles.ReadStart under its own deadline, logged on failure.
// in: parent ctx, device. out: read start, error.
func (s *Server) readStart(parentCtx context.Context, device *service.Device) (time.Time, error) {
	ctx, cancel := context.WithTimeout(parentCtx, snapshotUpsertTimeout)
	defer cancel()
	t, err := s.services.DeviceFiles.ReadStart(ctx, device.TenantID)
	if err != nil {
		slog.Error("device read start failed", "device", device.DeviceID, "err", err)
	}
	return t, err
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

// changesConfig reports whether a CLI command can rewrite config.json on the device.
// fs.format wipes it, a firmware update from ota.* can migrate it, a glob can match it.
func changesConfig(command, payload string) bool {
	switch command {
	case "config.dump", "fs.cat", "fs.ls", "fs.df", "ota.status":
		return false
	case "fs.format":
		return true
	}
	return strings.HasPrefix(command, "config.") || strings.HasPrefix(command, "ota.") ||
		(strings.HasPrefix(command, "fs.") &&
			(strings.Contains(payload, configSnapshotKey) || strings.ContainsAny(payload, "*?")))
}

// snapshotFromCmdResponse stores a config.dump answer through the device read
// path, under its own deadline rather than what the CLI round trip left over.
// in: parent ctx, tenant, device pk, response, user id, read start. out: none.
func (s *Server) snapshotFromCmdResponse(parentCtx context.Context, tenantID string, devicePk uuid.UUID, resp *mqtt.CLIResponse, userID *uuid.UUID, readStart time.Time) {
	content := joinOutput(resp.Output)
	if content == "" {
		return
	}
	ctx, cancel := context.WithTimeout(parentCtx, snapshotUpsertTimeout)
	defer cancel()
	h := sha256.Sum256([]byte(content))
	hashHex := hex.EncodeToString(h[:])
	if _, err := s.services.DeviceFiles.UpsertFromDevice(ctx, tenantID, devicePk, configSnapshotKey, content, hashHex, "read", userID, readStart); err != nil {
		slog.Error("device_file upsert failed", "path", configSnapshotKey, "err", err)
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
// goroutine runs stagedWrite, each step bounded by cfg.CLIRequestTimeout.
// The final summary lands in the store as a synthetic CLIResponse with output
// lines "<bytes> bytes in <n> chunk(s)".
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
	if service.IsConfigJSON(req.Path) {
		req.Content = service.BlankMaskMarkers(req.Content)
	}
	if msg := firmwareRefusal(device, "Saving a file"); msg != "" {
		http.Error(w, msg, http.StatusConflict)
		return
	}
	// Two writes would share <path>.new and interleave their chunks on the device.
	claim, ok := s.claimDeviceWrite(device.ID, writeClaimTTL(s.cfg.CLIRequestTimeout, len(req.Content)))
	if !ok {
		http.Error(w, "a write to this device is already running", http.StatusConflict)
		return
	}
	// Checked under the claim, so no other write can change the store in between.
	if msg := configWriteRefusal(req.Path, req.Content, s.blankSecretLookup(r.Context(), device, req.Content)); msg != "" {
		s.releaseDeviceWrite(device.ID, claim)
		http.Error(w, msg, http.StatusUnprocessableEntity)
		return
	}

	topicPrefix := s.deviceTopicPrefix(device)
	user := authmw.CurrentUser(r)
	slog.Info("admin config write enqueue",
		"user", user.Email, "device", device.DeviceID,
		"path", req.Path, "content_len", len(req.Content))

	h := sha256.Sum256([]byte(req.Content))
	s.audit(r.Context(), user, authz.DeviceConfigWrite, service.AuditEntry{
		TargetType: "device", TargetID: device.ID.String(), TenantID: device.TenantID,
		Detail: map[string]any{"device_id": device.DeviceID, "path": req.Path,
			"bytes": len(req.Content), "sha256": hex.EncodeToString(h[:])},
	})
	reqID := s.cliRequests.enqueue()
	// Detached goroutine - same rationale as runCLICmd above: the async CLI
	// proxy outlives the HTTP request, so WithoutCancel sheds r.Context()
	// cancellation while keeping its values. stagedWrite applies the
	// CLIRequestTimeout deadline per step.
	cliCtx := context.WithoutCancel(r.Context())
	s.goCLI(reqID, "web.cli_write", device.DeviceID, func() {
		s.runCLIWrite(cliCtx, reqID, claim, device, topicPrefix, req.Path, req.Content, &user.ID)
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cliEnqueueResponse{
		RequestID:      reqID.String(),
		TimeoutSeconds: int(s.cfg.CLIRequestTimeout.Seconds()) * writeSteps(len(req.Content)),
	})
}

// runCLIWrite is the goroutine body for an enqueued chunked write. On
// success the snapshot row is upserted and the entry is marked done with a
// summary. On failure the entry carries the stagedWrite status and message.
// in: request id, claim token, device, topic prefix, path, content, user id. out: none (writes to store).
// parentCtx: request-derived non-cancellable context (see runCLICmd).
// snapshotUpsertTimeout bounds the snapshot row write that runs while the device write claim is held.
const snapshotUpsertTimeout = 10 * time.Second

func (s *Server) runCLIWrite(parentCtx context.Context, reqID, claim uuid.UUID, device *service.Device, topicPrefix, path, content string, userID *uuid.UUID) {
	defer s.releaseDeviceWrite(device.ID, claim)
	// A stall between claim and here (the audit write) may have let another write take over.
	if !s.renewDeviceWrite(device.ID, claim, writeClaimTTL(s.cfg.CLIRequestTimeout, len(content))) {
		s.cliRequests.markError(reqID, reqStatusError, "another write took over this device, nothing was sent")
		return
	}
	configPath := service.IsConfigJSON(path)
	var prevChange *time.Time
	// Again at write time: the markers may have gone stale since the enqueue check.
	if configPath {
		// A read marker goes out as "", which the guard then checks on the device.
		content = service.BlankMaskMarkers(content)
		if msg := configWriteRefusal(path, content, s.blankSecretLookup(parentCtx, device, content)); msg != "" {
			s.releaseDeviceWrite(device.ID, claim)
			s.cliRequests.markError(reqID, reqStatusError, msg)
			return
		}
		// The lookup may have outlived the claim, so a write that took it over owns the device.
		if !s.renewDeviceWrite(device.ID, claim, writeClaimTTL(s.cfg.CLIRequestTimeout, len(content))) {
			s.cliRequests.markError(reqID, reqStatusError, "another write took over this device, nothing was sent")
			return
		}
		// After the guard, which needs the markers current. Without the mark nothing is sent.
		// It spans the claim, so a read of the old file stays stale if the mark after the rename fails.
		var err error
		if prevChange, err = s.markConfigChanging(parentCtx, device, writeClaimTTL(s.cfg.CLIRequestTimeout, len(content))); err != nil {
			s.releaseDeviceWrite(device.ID, claim)
			s.cliRequests.markError(reqID, reqStatusError, "could not record the config change, nothing was sent")
			return
		}
	}
	contentBytes := []byte(content)
	if err := stagedWrite(parentCtx, s.mqtt, s.cfg.CLIRequestTimeout, topicPrefix, path, contentBytes); err != nil {
		var f *writeFailure
		errors.As(err, &f)
		// Closes the window either way: an unknown rename counts as a change, a failed one changed nothing.
		if configPath {
			if merr := s.endConfigChange(parentCtx, device, prevChange); merr != nil {
				slog.Error("mark config changed after a failed write", "device", device.DeviceID, "err", merr)
			}
		}
		// Release before the entry turns terminal, so a write posted on 'done' is not a 409.
		s.releaseDeviceWrite(device.ID, claim)
		if f != nil {
			s.cliRequests.markError(reqID, f.status, f.msg)
		} else {
			s.cliRequests.markError(reqID, reqStatusError, err.Error())
		}
		return
	}

	h := sha256.Sum256(contentBytes)
	hashHex := hex.EncodeToString(h[:])
	// stagedWrite verified the bytes on the device, so they are device truth from here on.
	if err := s.storeWritten(parentCtx, device, path, content, hashHex, userID, prevChange); err != nil {
		slog.Error("write device_file upsert failed", "path", path, "err", err)
		// Only config.json feeds the guard. Elsewhere the row is a snapshot and the write stands.
		if configPath {
			// Once more, so Load from device is not held off until the window ends.
			if merr := s.endConfigChange(parentCtx, device, prevChange); merr != nil {
				slog.Error("mark config changed after a failed store", "device", device.DeviceID, "err", merr)
			}
			s.releaseDeviceWrite(device.ID, claim)
			s.cliRequests.markError(reqID, reqStatusError, fmt.Sprintf(
				"%d bytes written to config.json on the device, but the app could not record them. "+
					"Load from device on the config page to refresh", len(contentBytes)))
			return
		}
	}
	s.releaseDeviceWrite(device.ID, claim)

	s.cliRequests.markDone(reqID, &mqtt.CLIResponse{
		Cmd: "fs.write",
		OK:  true,
		Output: []string{
			fmt.Sprintf("%d bytes in %d chunk(s)", len(contentBytes), writeChunkCount(len(contentBytes))),
		},
	})
}

// storeWritten stores confirmed written content. config.json closes its change window first, in
// its own tx, so a failed refresh still leaves older markers stale. out: error.
func (s *Server) storeWritten(parentCtx context.Context, device *service.Device, path, content, hashHex string, userID *uuid.UUID, prevChange *time.Time) error {
	ctx, cancel := context.WithTimeout(parentCtx, snapshotUpsertTimeout)
	defer cancel()
	if !service.IsConfigJSON(path) {
		return s.services.DeviceFiles.Upsert(ctx, device.TenantID, device.ID, path, content, hashHex, "write", userID)
	}
	if err := s.services.DeviceFiles.EndConfigChange(ctx, device.TenantID, device.ID, prevChange); err != nil {
		return err
	}
	start, err := s.services.DeviceFiles.ReadStart(ctx, device.TenantID)
	if err != nil {
		return err
	}
	_, err = s.services.DeviceFiles.UpsertFromDevice(ctx, device.TenantID, device.ID, path, content, hashHex, "write", userID, start)
	return err
}

// writeClaim is one running write: the token its owner releases with, and
// when a claim its owner never released stops blocking the device.
type writeClaim struct {
	token   uuid.UUID
	expires time.Time
}

// writeClaimTTL outlasts every bounded step of an n-byte write plus the snapshot upsert.
// in: per-step timeout, content bytes. out: claim lifetime.
func writeClaimTTL(step time.Duration, n int) time.Duration {
	return time.Duration(writeSteps(n))*step + snapshotUpsertTimeout + time.Minute
}

// claimDeviceWrite marks a write to the device as running. A claim past its
// expiry is taken over. in: device id, ttl. out: token, false if a live claim exists.
func (s *Server) claimDeviceWrite(id uuid.UUID, ttl time.Duration) (uuid.UUID, bool) {
	c := writeClaim{token: uuid.New(), expires: time.Now().Add(ttl)}
	for {
		old, busy := s.deviceWrites.LoadOrStore(id, c)
		if !busy {
			return c.token, true
		}
		if time.Now().Before(old.(writeClaim).expires) {
			return uuid.Nil, false
		}
		if s.deviceWrites.CompareAndSwap(id, old, c) {
			slog.Warn("device.write_claim.expired_taken", "device", id)
			return c.token, true
		}
	}
}

// renewDeviceWrite restarts the claim token holds at ttl from now, so the
// worker gets the whole lifetime. in: device id, token, ttl. out: false if
// another write took the claim over.
func (s *Server) renewDeviceWrite(id, token uuid.UUID, ttl time.Duration) bool {
	for {
		old, ok := s.deviceWrites.Load(id)
		if !ok || old.(writeClaim).token != token {
			return false
		}
		if s.deviceWrites.CompareAndSwap(id, old, writeClaim{token: token, expires: time.Now().Add(ttl)}) {
			return true
		}
	}
}

// releaseDeviceWrite ends the claim token holds. A second release, or one
// after another write took over the device, is a no-op.
// in: device id, token. out: none.
func (s *Server) releaseDeviceWrite(id, token uuid.UUID) {
	if v, ok := s.deviceWrites.Load(id); ok && v.(writeClaim).token == token {
		s.deviceWrites.CompareAndDelete(id, v)
	}
}

// cliSender is the part of *mqtt.Client that stagedWrite drives.
type cliSender interface {
	CLIRequest(ctx context.Context, topicPrefix, command, payload string) (*mqtt.CLIResponse, error)
	CLIRequestStateful(ctx context.Context, topicPrefix, command, payload string) (*mqtt.CLIResponse, error)
	CLIRequestRaw(ctx context.Context, topicPrefix, command string, rawPayload []byte) (*mqtt.CLIResponse, error)
}

const (
	// configSnapshotKey is the device_files path drift and read snapshots store config under.
	configSnapshotKey = "config.json"
	// Leaves room for path + newline under the device buffer_in (4096).
	writeChunkSize = 3900
	// Not .tmp: the firmware stages its own config saves there.
	stagedSuffix = ".new"
	// The firmware's fs.write path buffer, NUL included (kPathCap).
	fwPathCap = 64
)

// writeChunkCount is how many fs.write/fs.append chunks n bytes take.
func writeChunkCount(n int) int { return (n + writeChunkSize - 1) / writeChunkSize }

// readbackChunkSize is one fs.cat read when a timed-out rename is checked.
const readbackChunkSize = 2048

// writeSteps is the CLI round trips a write may take: chunks, fs.cat, fs.mv,
// the staging check, then fs.rm or a full readback of the destination, plus a
// read of a masked staged copy.
func writeSteps(n int) int {
	return writeChunkCount(n) + 3 + max(1, (n+readbackChunkSize-1)/readbackChunkSize) + maskedReadSteps(n)
}

// maskedReadSteps bounds the read of a masked staged copy of n bytes. Markers and
// pretty printing grow the copy, escaping shrinks each chunk.
func maskedReadSteps(n int) int { return max(1, (4*n+readbackChunkSize-1)/readbackChunkSize) }

// configWriteRefusal stops a config.json write with empty secret fields, which would erase the device's secrets (#85).
// An empty field passes only when check says so (#88). in: path, content, check (nil refuses all). out: message or "".
func configWriteRefusal(path, content string, check func(field string) (bool, error)) string {
	if !service.IsConfigJSON(path) {
		return ""
	}
	fields, unknown, err := service.BlankSecretFields(content)
	if err != nil {
		return "config.json is not one JSON object, nothing was sent"
	}
	if len(unknown) > 0 {
		return fmt.Sprintf("config.json has %s empty and the app cannot check it on the device. "+
			"Enter its value, or leave the key out if the device does not use it, nothing was sent", strings.Join(unknown, ", "))
	}
	const refusal = "config.json has empty secret fields (snapshots and the editor never show secrets), " +
		"writing it would erase the device's secrets. Change settings with Push config keys, nothing was sent"
	if len(fields) > 0 && check == nil {
		return refusal
	}
	for _, f := range fields {
		if ok, err := check(f); err != nil || !ok {
			var r guardRefusal
			if errors.As(err, &r) {
				return string(r)
			}
			return refusal
		}
	}
	return ""
}

// firmwareRefusal stops a staged write before dispatch on firmware that does not echo req_id,
// whose size check could never pass. Unknown firmware is refused too. in: device, action. out: message or "".
func firmwareRefusal(d *service.Device, action string) string {
	if service.FirmwareMeetsFloor(d.FirmwareVersion) {
		return ""
	}
	reported := "no firmware version"
	if d.FirmwareVersion != nil && *d.FirmwareVersion != "" {
		reported = "firmware " + *d.FirmwareVersion
	}
	return fmt.Sprintf("%s needs firmware %s or later and this device reports %s. "+
		"Update the firmware first, nothing was sent", action, service.MinFirmwareVersion, reported)
}

// guardRefusal is a write guard refusal with its own message.
type guardRefusal string

func (g guardRefusal) Error() string { return string(g) }

// blankSecretLookup checks an empty secret field against the device, with one correlated secret.info
// per write. A scalar passes when NVS holds it, as the firmware reads NVS first. A WiFi password passes
// when a current read showed "" for the SSID and NVS holds none. in: ctx, device, content. out: check.
func (s *Server) blankSecretLookup(ctx context.Context, device *service.Device, content string) func(string) (bool, error) {
	var nvs map[string]string
	asked, reachable := false, false
	state := func() {
		if !asked {
			asked = true
			fields, _, _ := service.BlankSecretFields(content)
			nvs, reachable = s.verifiedSecretState(ctx, device, fields)
		}
	}
	return func(field string) (bool, error) {
		ssid, wifi := strings.CutPrefix(field, service.WifiPasswordPrefix)
		if !wifi {
			state()
			switch {
			case !reachable:
				return false, guardRefusal(fmt.Sprintf("the device did not confirm over secret.info, with the request id, "+
					"that NVS holds %s, nothing was sent", field))
			case nvs[field] != "nvs":
				return false, guardRefusal(fmt.Sprintf("the device does not hold %s in NVS, so an empty value in config.json "+
					"would erase it. Enter its value or push it with Push config keys first, nothing was sent", field))
			}
			return true, nil
		}
		if ssid == "" {
			return false, nil
		}
		// A timed-out lookup is an error, which refuses the write.
		qctx, cancel := context.WithTimeout(ctx, snapshotUpsertTimeout)
		open, err := s.services.DeviceFiles.OpenNetworkCurrent(qctx, device.TenantID, device.ID, ssid)
		cancel()
		if err != nil || !open {
			return false, err
		}
		state()
		switch {
		case !reachable:
			return false, guardRefusal(fmt.Sprintf("the device did not confirm over secret.info, with the request id, "+
				"that NVS holds no password for %q, nothing was sent", ssid))
		case nvs[field] == "nvs":
			return false, guardRefusal(fmt.Sprintf("the device holds a password for %q in NVS, so config.json "+
				"cannot carry it empty. Use Push config keys or Clear on device first, nothing was sent", ssid))
		case nvs[field] == "":
			return false, guardRefusal(fmt.Sprintf("secret.info cannot tell %q apart from another SSID, nothing was sent", ssid))
		}
		return true, nil
	}
}

// writeFailure is a failed stagedWrite: the request store status plus the UI message.
// liveMayHaveChanged is set when the rename was sent and its outcome is unknown.
type writeFailure struct {
	status             requestStatus
	msg                string
	liveMayHaveChanged bool
}

func (f *writeFailure) Error() string { return f.msg }

// ackBytesRE reads the byte count and path out of the firmware fs.write/fs.append ack.
var ackBytesRE = regexp.MustCompile(`^(?:Wrote|Appended) (\d+) bytes to (.+)$`)

// stagedWrite sends content to path+".new" in chunks and renames it over path
// only after every chunk acked its full length, so a failure leaves path as it was.
// in: ctx, sender, per-step timeout, topic prefix, path, content. out: nil or *writeFailure.
func stagedWrite(parentCtx context.Context, cli cliSender, timeout time.Duration, topicPrefix, path string, content []byte) error {
	// "config.json" is the snapshot key for the root config. Firmware wants the slash.
	if path == configSnapshotKey {
		path = "/" + configSnapshotKey
	}
	// The shell splits fs.mv and fs.rm args on blanks and globs * and ?.
	if strings.ContainsAny(path, " \t\r\n*?") {
		return &writeFailure{status: reqStatusError, msg: "path must not contain whitespace, * or ?"}
	}
	// FAT rename refuses an existing target, so /sd has no atomic replace.
	if path == "/sd" || strings.HasPrefix(path, "/sd/") {
		return &writeFailure{status: reqStatusError, msg: "files on /sd cannot be replaced atomically, the FAT rename refuses an existing file"}
	}
	staged := path + stagedSuffix
	if len(staged) >= fwPathCap {
		return &writeFailure{status: reqStatusError, msg: fmt.Sprintf("path too long: the device takes paths up to %d bytes, and the staging copy adds %d",
			fwPathCap-1-len(stagedSuffix), len(stagedSuffix))}
	}
	total := writeChunkCount(len(content))

	step := func(label string, send func(context.Context) (*mqtt.CLIResponse, error)) (*mqtt.CLIResponse, *writeFailure) {
		ctx, cancel := context.WithTimeout(parentCtx, timeout)
		defer cancel()
		resp, err := send(ctx)
		switch {
		case err != nil && ctx.Err() == context.DeadlineExceeded:
			return nil, &writeFailure{status: reqStatusTimeout, msg: fmt.Sprintf("%s timed out after %s", label, timeout)}
		case err != nil:
			return nil, &writeFailure{status: reqStatusError, msg: fmt.Sprintf("%s failed: %v", label, err)}
		case !resp.OK:
			return resp, &writeFailure{status: reqStatusError, msg: fmt.Sprintf("%s device error: %v", label, resp.Output)}
		}
		return resp, nil
	}
	// The live file was never touched. Drop the staging copy, best effort.
	cleanup := func(f *writeFailure) error {
		resp, _ := step("remove "+staged, func(ctx context.Context) (*mqtt.CLIResponse, error) {
			return cli.CLIRequest(ctx, topicPrefix, "fs.rm", staged)
		})
		if resp == nil || !outputHasPrefix(resp.Output, "Removed ") {
			f.msg += fmt.Sprintf(" (%s may remain on the device, the next save overwrites it)", staged)
		}
		return f
	}

	for i := 0; i < total; i++ {
		start := i * writeChunkSize
		end := min(start+writeChunkSize, len(content))
		chunk := content[start:end]

		cmd := "fs.write"
		if i > 0 {
			cmd = "fs.append"
		}
		payload := make([]byte, 0, len(staged)+1+len(chunk))
		payload = append(payload, staged...)
		payload = append(payload, '\n')
		payload = append(payload, chunk...)

		label := fmt.Sprintf("chunk %d/%d", i+1, total)
		resp, f := step(label, func(ctx context.Context) (*mqtt.CLIResponse, error) {
			return cli.CLIRequestRaw(ctx, topicPrefix, cmd, payload)
		})
		if f != nil {
			// A first chunk the device refused created nothing to clean up.
			if i == 0 && resp != nil {
				return f
			}
			return cleanup(f)
		}
		if n, ok := ackedBytes(resp.Output, staged); !ok || n != len(chunk) {
			return cleanup(&writeFailure{status: reqStatusError, msg: fmt.Sprintf("%s short write: device replied %q for %d bytes", label, strings.Join(resp.Output, " "), len(chunk))})
		}
	}

	// The ack counts bytes before f.close, which can still fail on a full LittleFS.
	label := "size check of " + staged
	resp, f := step(label, func(ctx context.Context) (*mqtt.CLIResponse, error) {
		// Offset at the expected end: the reply carries total and no data.
		return cli.CLIRequestStateful(ctx, topicPrefix, "fs.cat", fmt.Sprintf("%s %d 1", staged, len(content)))
	})
	if f != nil {
		return cleanup(f)
	}
	if resp.Total == nil || (*resp.Total != len(content) && !maskedCopyMatches(step, cli, topicPrefix, staged, content, *resp.Total)) {
		got := "no size"
		if resp.Total != nil {
			got = strconv.Itoa(*resp.Total) + " bytes"
		}
		return cleanup(&writeFailure{status: reqStatusError, msg: fmt.Sprintf("%s: device holds %s, want %d", label, got, len(content))})
	}

	label = "rename " + staged + " to " + path
	resp, f = step(label, func(ctx context.Context) (*mqtt.CLIResponse, error) {
		return cli.CLIRequest(ctx, topicPrefix, "fs.mv", staged+" "+path)
	})
	if f != nil && f.status == reqStatusTimeout {
		return renameReadback(f, step, cleanup, cli, topicPrefix, staged, path, content)
	}
	if f != nil {
		return cleanup(f)
	}
	// fs.mv prints its failure with ok:true, so only the Renamed line counts.
	if !outputHasPrefix(resp.Output, "Renamed ") {
		return cleanup(&writeFailure{status: reqStatusError, msg: fmt.Sprintf("%s failed: %s", label, strings.Join(resp.Output, " "))})
	}
	return nil
}

// maskedCopyMatches reads the staged copy whole and compares it masked. Masked
// firmware serves a config-shaped file with secrets as markers and reports that
// size. in: step, sender, topic prefix, staged path, content, reported size. out: match.
func maskedCopyMatches(step writeStep, cli cliSender, topicPrefix, staged string, content []byte, total int) bool {
	if !strings.HasPrefix(strings.TrimSpace(string(content)), "{") {
		return false
	}
	var b strings.Builder
	for i, off := 0, 0; off < total; i++ {
		if i == maskedReadSteps(len(content)) {
			return false
		}
		resp, f := step("read back "+staged, func(ctx context.Context) (*mqtt.CLIResponse, error) {
			return cli.CLIRequestStateful(ctx, topicPrefix, "fs.cat", fmt.Sprintf("%s %d %d", staged, off, readbackChunkSize))
		})
		if f != nil || resp.Total == nil || *resp.Total != total || resp.Data == nil ||
			resp.Offset == nil || *resp.Offset != off || *resp.Data == "" {
			return false
		}
		b.WriteString(*resp.Data)
		off += len(*resp.Data)
	}
	return b.Len() == total && service.MaskedConfigEqual(string(content), b.String())
}

// writeStep is stagedWrite's bounded CLI round trip.
type writeStep func(label string, send func(context.Context) (*mqtt.CLIResponse, error)) (*mqtt.CLIResponse, *writeFailure)

// renameReadback settles an fs.mv that timed out: the staging copy still there
// means no rename, gone with path holding exactly content means it landed, else unknown.
// in: the timeout, step, cleanup, sender, topic prefix, staged, path, content. out: nil or *writeFailure.
func renameReadback(timedOut *writeFailure, step writeStep, cleanup func(*writeFailure) error, cli cliSender, topicPrefix, staged, path string, content []byte) error {
	read := func(p string, off, n int) (*mqtt.CLIResponse, *writeFailure) {
		return step("read back "+p, func(ctx context.Context) (*mqtt.CLIResponse, error) {
			return cli.CLIRequestStateful(ctx, topicPrefix, "fs.cat", fmt.Sprintf("%s %d %d", p, off, n))
		})
	}
	unknown := &writeFailure{status: reqStatusTimeout, msg: timedOut.msg + ", the rename outcome is unknown. Reload the file to check it",
		liveMayHaveChanged: true}
	size := len(content)
	resp, f := read(staged, size, 1)
	switch {
	case f == nil && resp.Total != nil && *resp.Total == size:
		return cleanup(timedOut)
	case f == nil || resp == nil || !outputHasPrefix(resp.Output, "File not found"):
		return unknown
	}
	// A size match alone could be another file, so the bytes must match too.
	for off := 0; off < size; {
		resp, f = read(path, off, readbackChunkSize)
		// A late reply without req_id can carry another offset's bytes.
		if f != nil || resp.Total == nil || *resp.Total != size || resp.Data == nil ||
			resp.Offset == nil || *resp.Offset != off {
			return unknown
		}
		end := off + len(*resp.Data)
		if end == off || end > size || *resp.Data != string(content[off:end]) {
			return unknown
		}
		off = end
	}
	slog.Warn("device.file_write.rename_confirmed", "path", path, "reason", "fs.mv reply timed out")
	return nil
}

// ackedBytes parses the byte count of an fs.write/fs.append ack for staged.
// The firmware cuts the ack at 64 bytes, so its path need only prefix staged.
func ackedBytes(output []string, staged string) (int, bool) {
	if len(output) == 0 {
		return 0, false
	}
	m := ackBytesRE.FindStringSubmatch(output[0])
	if m == nil || !strings.HasPrefix(staged, m[2]) {
		return 0, false
	}
	n, err := strconv.Atoi(m[1])
	return n, err == nil
}

// outputHasPrefix reports whether any output line starts with prefix.
func outputHasPrefix(output []string, prefix string) bool {
	for _, l := range output {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

// configLoadChunkCap bounds the poll budget of a Load from device, 64 chunks of 2 KB.
const configLoadChunkCap = 64

// handleAdminDeviceConfigLoad enqueues Load from device: a server-side chunked read of /config.json
// through the device read path, so markers and the snapshot follow it. out: JSON enqueue ack.
func (s *Server) handleAdminDeviceConfigLoad(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "bad device id", http.StatusBadRequest)
		return
	}
	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil {
		slog.Error("device lookup failed", "device", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}
	user := authmw.CurrentUser(r)
	// One row for the whole read, as the CLI box records each command.
	s.audit(r.Context(), user, authz.DeviceCommand, service.AuditEntry{
		TargetType: "device", TargetID: device.ID.String(), TenantID: device.TenantID,
		Detail: map[string]any{"device_id": device.DeviceID, "command": "config.load", "payload_bytes": 0},
	})
	reqID := s.cliRequests.enqueue()
	cliCtx := context.WithoutCancel(r.Context())
	s.goCLI(reqID, "web.config_load", device.DeviceID, func() {
		s.runConfigLoad(cliCtx, reqID, device, &user.ID)
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cliEnqueueResponse{
		RequestID:      reqID.String(),
		TimeoutSeconds: int(s.cfg.CLIRequestTimeout.Seconds()) * configLoadChunkCap,
	})
}

// runConfigLoad stores the read, then hands the raw file to the editor in data.
// A failed store is logged, the load stands.
func (s *Server) runConfigLoad(parentCtx context.Context, reqID uuid.UUID, device *service.Device, userID *uuid.UUID) {
	start, err := s.readStart(parentCtx, device)
	if err != nil {
		s.cliRequests.markError(reqID, reqStatusError, "could not start the device read, nothing was sent")
		return
	}
	content, err := s.mqtt.ReadFileChunked(parentCtx, s.deviceTopicPrefix(device), "/"+configSnapshotKey, s.cfg.CLIRequestTimeout)
	if err != nil {
		s.cliRequests.markError(reqID, reqStatusError, "load failed: "+err.Error())
		return
	}
	var probe map[string]any
	if json.Unmarshal([]byte(content), &probe) == nil && probe != nil {
		ctx, cancel := context.WithTimeout(parentCtx, snapshotUpsertTimeout)
		h := sha256.Sum256([]byte(content))
		if _, err := s.services.DeviceFiles.UpsertFromDevice(ctx, device.TenantID, device.ID, configSnapshotKey,
			content, hex.EncodeToString(h[:]), "read", userID, start); err != nil {
			slog.Error("config load upsert failed", "device", device.DeviceID, "err", err)
		}
		cancel()
	}
	done := true
	// The editor shows a masked secret blank, as snapshots do.
	shown := service.BlankMaskMarkers(content)
	s.cliRequests.markDone(reqID, &mqtt.CLIResponse{Cmd: "fs.cat", OK: true, Done: &done, Data: &shown})
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
