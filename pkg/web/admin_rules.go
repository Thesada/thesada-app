package web

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service"
)

const (
	ruleSlotRulesLua = "rules.lua"
	// Cap workspace POST bodies. Blockly JSON for a dense ruleset is small;
	// this is a DoS backstop, not a product limit.
	maxRuleWorkspaceBody = 1 << 20 // 1 MiB
)

func (s *Server) handleAdminDeviceRules(w http.ResponseWriter, r *http.Request) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.NotFound(w, r)
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

	s.render(w, r, "admin-device-rules.html", map[string]interface{}{
		"Device":            device,
		"TopicPrefix":       s.deviceTopicPrefix(device),
		"CLITimeoutSeconds": int(s.cfg.CLIRequestTimeout.Seconds()),
		"RuleSlot":          ruleSlotRulesLua,
	})
}

type ruleWorkspaceSaveRequest struct {
	Slot          string `json:"slot"`
	WorkspaceJSON string `json:"workspace_json"`
	LuaContent    string `json:"lua_content"`
	Source        string `json:"source"`
}

// handleAdminDeviceRulesWorkspaceGET returns the saved Blockly workspace for
// a device slot, or {exists:false} when none has been saved yet.
// in: writer, request (?slot=). out: JSON.
func (s *Server) handleAdminDeviceRulesWorkspaceGET(w http.ResponseWriter, r *http.Request) {
	_, device, ok := s.adminDeviceFromPath(w, r)
	if !ok {
		return
	}
	slot := r.URL.Query().Get("slot")
	if slot == "" {
		slot = ruleSlotRulesLua
	}
	if !service.ValidRuleSlot(slot) {
		http.Error(w, "invalid slot", http.StatusBadRequest)
		return
	}
	ws, err := s.services.RuleWorkspaces.Latest(r.Context(), device.TenantID, device.ID, slot)
	if err != nil {
		slog.Error("rule.workspace.load_failed", "device", device.DeviceID, "slot", slot, "err", err)
		http.Error(w, "workspace load failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if ws == nil {
		_ = json.NewEncoder(w).Encode(map[string]any{"exists": false, "slot": slot})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"exists":         true,
		"slot":           ws.Slot,
		"workspace_json": ws.WorkspaceJSON,
		"lua_content":    ws.LuaContent,
		"lua_sha256":     ws.LuaSHA256,
		"source":         ws.Source,
		"updated_at":     ws.UpdatedAt,
	})
}

// handleAdminDeviceRulesWorkspacePOST persists Blockly workspace JSON + the
// generated Lua for a device slot. Does not push to the device; Push still
// goes through /config/write.
// in: writer, request (JSON body). out: JSON {ok, lua_sha256}.
func (s *Server) handleAdminDeviceRulesWorkspacePOST(w http.ResponseWriter, r *http.Request) {
	_, device, ok := s.adminDeviceFromPath(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleWorkspaceBody)
	var req ruleWorkspaceSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if err == io.EOF {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Slot == "" {
		req.Slot = ruleSlotRulesLua
	}
	if !service.ValidRuleSlot(req.Slot) {
		http.Error(w, "invalid slot", http.StatusBadRequest)
		return
	}
	if req.WorkspaceJSON == "" {
		http.Error(w, "workspace_json required", http.StatusBadRequest)
		return
	}
	user := authmw.CurrentUser(r)
	sha, err := s.services.RuleWorkspaces.Save(
		r.Context(), device.TenantID, device.ID,
		req.Slot, req.WorkspaceJSON, req.LuaContent, req.Source, &user.ID,
	)
	if err != nil {
		slog.Error("rule.workspace.save_failed",
			"user", user.Email, "device", device.DeviceID, "slot", req.Slot, "err", err)
		http.Error(w, "workspace save failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "slot": req.Slot, "lua_sha256": sha})
}

// adminDeviceFromPath resolves the {id} path param to a device for
// super-admin handlers. Writes 4xx/5xx and returns ok=false on failure.
func (s *Server) adminDeviceFromPath(w http.ResponseWriter, r *http.Request) (uuid.UUID, *service.Device, bool) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "bad device id", http.StatusBadRequest)
		return uuid.Nil, nil, false
	}
	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil {
		slog.Error("device lookup failed", "device", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return uuid.Nil, nil, false
	}
	if device == nil {
		http.NotFound(w, r)
		return uuid.Nil, nil, false
	}
	return id, device, true
}
