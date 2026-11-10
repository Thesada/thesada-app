package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/authz"
	"thesada.app/app/pkg/rulesgen"
	"thesada.app/app/pkg/service"
)

// Tenant rules editor (#2). The browser sends Blockly JSON only: the server
// generates the Lua, saves both, and pushes what it generated itself.

const (
	tenantRuleSource = "tenant"
	tenantRulePath   = "/scripts/" + service.DefaultRuleSlot
)

// rulePushResult is the terminal state of one tenant push.
type rulePushResult struct {
	Written  bool   `json:"written"`
	Reloaded bool   `json:"reloaded"`
	SHA256   string `json:"lua_sha256"`
}

// canEditRules: an operator, a tenant admin of the device's tenant, or the device owner.
// in: caller, device. out: may save and push.
func canEditRules(me *service.User, d *service.Device) bool {
	if me == nil || d == nil {
		return false
	}
	if authz.Can(me, authz.RulesTenantPush) {
		return true
	}
	if me.TenantID != d.TenantID {
		return false
	}
	return me.IsAdmin || (d.OwnerUserID != nil && *d.OwnerUserID == me.ID)
}

// rulesDevice resolves {id} in the caller's scope, answering 404 or 500 itself.
func (s *Server) rulesDevice(w http.ResponseWriter, r *http.Request) (*service.Device, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return nil, false
	}
	d, err := s.deviceInScope(r, id, authz.DeviceReadCrossTenant)
	if err != nil {
		slog.Error("rules.device_lookup_failed", "id", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return nil, false
	}
	if d == nil {
		http.NotFound(w, r)
		return nil, false
	}
	return d, true
}

// latestTenantRules loads the saved workspace and whether an operator owns the
// slot (saved from the admin editor, whose blocks this editor does not have).
func (s *Server) latestTenantRules(ctx context.Context, d *service.Device) (*service.DeviceRuleWorkspace, bool, error) {
	ws, err := s.services.RuleWorkspaces.Latest(ctx, d.TenantID, d.ID, service.DefaultRuleSlot)
	if err != nil {
		return nil, false, err
	}
	return ws, ws != nil && ws.Source != tenantRuleSource, nil
}

// handleDeviceRules renders the editor. Viewers get it read-only.
func (s *Server) handleDeviceRules(w http.ResponseWriter, r *http.Request) {
	d, ok := s.rulesDevice(w, r)
	if !ok {
		return
	}
	_, managed, err := s.latestTenantRules(r.Context(), d)
	if err != nil {
		slog.Error("rules.workspace_load_failed", "device", d.DeviceID, "err", err)
		http.Error(w, "rules load failed", http.StatusInternalServerError)
		return
	}
	me := authmw.CurrentUser(r)
	s.render(w, r, "device-rules.html", map[string]interface{}{
		"Device":   d,
		"CanEdit":  canEditRules(me, d),
		"Managed":  managed,
		"Operator": authz.Can(me, authz.RulesTenantPush),
		"Path":     tenantRulePath,
	})
}

// handleDeviceRulesWorkspaceGET returns the tenant workspace, never an operator's.
func (s *Server) handleDeviceRulesWorkspaceGET(w http.ResponseWriter, r *http.Request) {
	d, ok := s.rulesDevice(w, r)
	if !ok {
		return
	}
	ws, managed, err := s.latestTenantRules(r.Context(), d)
	if err != nil {
		slog.Error("rules.workspace_load_failed", "device", d.DeviceID, "err", err)
		http.Error(w, "rules load failed", http.StatusInternalServerError)
		return
	}
	out := map[string]any{"exists": false, "managed": managed}
	if ws != nil && !managed {
		out = map[string]any{"exists": true, "managed": false, "workspace_json": ws.WorkspaceJSON,
			"lua_sha256": ws.LuaSHA256, "updated_at": ws.UpdatedAt}
	}
	rulesJSON(w, http.StatusOK, out)
}

type tenantRulesBody struct {
	WorkspaceJSON string `json:"workspace_json"`
}

// readRules decodes the body and generates the Lua, answering 400 itself.
func readRules(w http.ResponseWriter, r *http.Request) (string, string, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleWorkspaceBody)
	var body tenantRulesBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.WorkspaceJSON == "" {
		http.Error(w, "workspace_json required", http.StatusBadRequest)
		return "", "", false
	}
	rules, err := rulesgen.Parse(body.WorkspaceJSON)
	if err != nil {
		http.Error(w, strings.TrimPrefix(err.Error(), rulesgen.ErrInvalid.Error()+": "), http.StatusBadRequest)
		return "", "", false
	}
	return body.WorkspaceJSON, rulesgen.Generate(rules), true
}

// handleDeviceRulesPreview shows the Lua a workspace becomes. Read-only, any viewer.
func (s *Server) handleDeviceRulesPreview(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.rulesDevice(w, r); !ok {
		return
	}
	_, lua, ok := readRules(w, r)
	if !ok {
		return
	}
	rulesJSON(w, http.StatusOK, map[string]any{"lua": lua})
}

// handleDeviceRulesSave stores the workspace and the Lua generated from it.
// An operator-owned slot is refused for tenants. An operator saving here hands it over.
func (s *Server) handleDeviceRulesSave(w http.ResponseWriter, r *http.Request) {
	d, ok := s.rulesDevice(w, r)
	if !ok {
		return
	}
	me := authmw.CurrentUser(r)
	if !canEditRules(me, d) {
		http.Error(w, "only a tenant admin or the device owner can change rules", http.StatusForbidden)
		return
	}
	wsJSON, lua, ok := readRules(w, r)
	if !ok {
		return
	}
	_, managed, err := s.latestTenantRules(r.Context(), d)
	if err != nil {
		slog.Error("rules.workspace_load_failed", "device", d.DeviceID, "err", err)
		http.Error(w, "rules load failed", http.StatusInternalServerError)
		return
	}
	if managed && !authz.Can(me, authz.RulesTenantPush) {
		http.Error(w, "rules on this device are managed by the operator", http.StatusConflict)
		return
	}
	sha, err := s.services.RuleWorkspaces.Save(r.Context(), d.TenantID, d.ID,
		service.DefaultRuleSlot, wsJSON, lua, tenantRuleSource, &me.ID)
	if err != nil {
		slog.Error("rules.workspace_save_failed", "device", d.DeviceID, "err", err)
		http.Error(w, "rules save failed", http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), me, authz.RulesTenantSave, service.AuditEntry{
		TargetType: "device", TargetID: d.ID.String(), TenantID: d.TenantID,
		Detail: map[string]any{"device_id": d.DeviceID, "lua_sha256": sha, "handover": managed},
	})
	rulesJSON(w, http.StatusOK, map[string]any{"ok": true, "lua_sha256": sha})
}

// handleDeviceRulesPush writes the saved rules to the device and reloads Lua.
// The Lua is generated again from the saved workspace, never taken from the client.
func (s *Server) handleDeviceRulesPush(w http.ResponseWriter, r *http.Request) {
	d, ok := s.rulesDevice(w, r)
	if !ok {
		return
	}
	me := authmw.CurrentUser(r)
	if !canEditRules(me, d) {
		http.Error(w, "only a tenant admin or the device owner can push rules", http.StatusForbidden)
		return
	}
	ws, managed, err := s.latestTenantRules(r.Context(), d)
	if err != nil {
		slog.Error("rules.workspace_load_failed", "device", d.DeviceID, "err", err)
		http.Error(w, "rules load failed", http.StatusInternalServerError)
		return
	}
	if ws == nil {
		http.Error(w, "save the rules before pushing", http.StatusBadRequest)
		return
	}
	if managed {
		http.Error(w, "rules on this device are managed by the operator", http.StatusConflict)
		return
	}
	rules, err := rulesgen.Parse(ws.WorkspaceJSON)
	if err != nil {
		http.Error(w, "saved rules no longer validate, save them again", http.StatusConflict)
		return
	}
	lua := rulesgen.Generate(rules)
	claim, ok := s.claimDeviceWrite(d.ID, writeClaimTTL(s.cfg.CLIRequestTimeout, len(lua))+s.cfg.CLIRequestTimeout)
	if !ok {
		http.Error(w, "a write to this device is already running", http.StatusConflict)
		return
	}
	sum := sha256.Sum256([]byte(lua))
	sha := hex.EncodeToString(sum[:])
	s.audit(r.Context(), me, authz.RulesTenantPush, service.AuditEntry{
		TargetType: "device", TargetID: d.ID.String(), TenantID: d.TenantID,
		Detail: map[string]any{"device_id": d.DeviceID, "path": tenantRulePath, "bytes": len(lua), "sha256": sha},
	})
	pushID := s.rulePushes.enqueue()
	s.rulePushOwner.Store(pushID, d.ID)
	ctx := context.WithoutCancel(r.Context())
	prefix := s.deviceTopicPrefix(d)
	go s.guardRulePush(pushID, d.DeviceID, func() {
		s.runRulePush(ctx, pushID, claim, d, prefix, lua, sha, me.ID)
	})
	rulesJSON(w, http.StatusOK, map[string]any{"request_id": pushID.String(),
		"timeout_seconds": int(s.cfg.CLIRequestTimeout.Seconds()) * (writeSteps(len(lua)) + 1)})
}

// guardRulePush turns a panic in the push into an error entry instead of a crash.
func (s *Server) guardRulePush(id uuid.UUID, deviceID string, body func()) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("rules.push_panic", "device", deviceID, "panic", p)
			s.rulePushes.markError(id, reqStatusError, "push failed")
		}
	}()
	body()
}

// runRulePush is the staged write (shared with the admin path) then lua.reload.
func (s *Server) runRulePush(ctx context.Context, id, claim uuid.UUID, d *service.Device, prefix, lua, sha string, userID uuid.UUID) {
	inner := s.cliRequests.enqueue()
	s.runCLIWrite(ctx, inner, claim, d, prefix, tenantRulePath, lua, &userID)
	e := s.cliRequests.get(inner)
	if e == nil || e.Status != reqStatusDone {
		msg := "write failed"
		if e != nil && e.ErrorMsg != "" {
			msg = e.ErrorMsg
		}
		s.rulePushes.markError(id, reqStatusError, msg)
		return
	}
	rctx, cancel := context.WithTimeout(ctx, s.cfg.CLIRequestTimeout)
	defer cancel()
	resp, err := s.mqtt.CLIRequest(rctx, prefix, "lua.reload", "")
	res := &rulePushResult{Written: true, SHA256: sha}
	switch {
	case err != nil:
		s.rulePushes.markError(id, reqStatusError, fmt.Sprintf("rules written, lua.reload got no answer: %v", err))
		return
	case !resp.OK:
		s.rulePushes.markError(id, reqStatusError, "rules written, lua.reload failed: "+strings.Join(resp.Output, " "))
		return
	}
	res.Reloaded = true
	s.rulePushes.markDone(id, res)
}

// handleDeviceRulesPushResult answers one push's state, only on its own device.
func (s *Server) handleDeviceRulesPushResult(w http.ResponseWriter, r *http.Request) {
	d, ok := s.rulesDevice(w, r)
	if !ok {
		return
	}
	id, err := uuid.Parse(r.URL.Query().Get("id"))
	if err != nil {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	owner, found := s.rulePushOwner.Load(id)
	e := s.rulePushes.get(id)
	if found && e == nil {
		s.rulePushOwner.Delete(id)
	}
	if !found || owner.(uuid.UUID) != d.ID || e == nil {
		rulesJSON(w, http.StatusOK, map[string]any{"status": "expired", "error": "push not found"})
		return
	}
	out := map[string]any{"status": string(e.Status)}
	if e.Response != nil {
		out["result"] = e.Response
	}
	if e.ErrorMsg != "" {
		out["error"] = e.ErrorMsg
	}
	if e.Status != reqStatusPending {
		s.rulePushOwner.Delete(id)
	}
	rulesJSON(w, http.StatusOK, out)
}

// rulesJSON writes v as a JSON response with status code.
func rulesJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
