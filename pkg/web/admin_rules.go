package web

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/authz"
	"thesada.app/app/pkg/service"
)

const (
	// Cap workspace POST bodies. Blockly JSON for a dense ruleset is small;
	// this is a DoS backstop, not a product limit.
	maxRuleWorkspaceBody = 1 << 20 // 1 MiB
)

func (s *Server) handleAdminDeviceRules(w http.ResponseWriter, r *http.Request) {
	device, ok := s.adminDeviceFromPath(w, r)
	if !ok {
		return
	}

	s.render(w, r, "admin-device-rules.html", map[string]interface{}{
		"Device":            device,
		"TopicPrefix":       s.deviceTopicPrefix(device),
		"CLITimeoutSeconds": int(s.cfg.CLIRequestTimeout.Seconds()),
		"RuleSlot":          service.DefaultRuleSlot,
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
	device, ok := s.adminDeviceFromPath(w, r)
	if !ok {
		return
	}
	slot := service.NormalizeRuleSlot(r.URL.Query().Get("slot"))
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
	device, ok := s.adminDeviceFromPath(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleWorkspaceBody)
	var req ruleWorkspaceSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	req.Slot = service.NormalizeRuleSlot(req.Slot)
	if !service.ValidRuleSlot(req.Slot) {
		http.Error(w, "invalid slot", http.StatusBadRequest)
		return
	}
	if req.WorkspaceJSON == "" {
		http.Error(w, "workspace_json required", http.StatusBadRequest)
		return
	}
	// WHY: the service requires a non-empty source; the visual editor is the
	// only caller today, so omitted source defaults here rather than silently
	// inside Save.
	if req.Source == "" {
		req.Source = "editor"
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
	s.audit(r.Context(), user, authz.RulesWorkspaceSave, service.AuditEntry{
		TargetType: "device", TargetID: device.ID.String(), TenantID: device.TenantID,
		Detail: map[string]any{"device_id": device.DeviceID, "slot": req.Slot, "lua_sha256": sha, "source": req.Source},
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "slot": req.Slot, "lua_sha256": sha})
}

type ruleTemplateSaveRequest struct {
	Name          string `json:"name"`
	WorkspaceJSON string `json:"workspace_json"`
	LuaContent    string `json:"lua_content"`
}

// handleAdminRuleTemplatesGET lists templates, or returns one workspace when name is set.
// in: writer, GET /admin/devices/{id}/rules/templates. out: JSON.
func (s *Server) handleAdminRuleTemplatesGET(w http.ResponseWriter, r *http.Request) {
	device, ok := s.adminDeviceFromPath(w, r)
	if !ok {
		return
	}
	name := r.URL.Query().Get("name")
	if name == "" {
		list, err := s.services.RuleTemplates.List(r.Context(), device.TenantID)
		if err != nil {
			slog.Error("rule.template.list_failed", "device", device.DeviceID, "err", err)
			http.Error(w, "template list failed", http.StatusInternalServerError)
			return
		}
		out := make([]map[string]string, 0, len(list))
		for _, t := range list {
			out = append(out, map[string]string{"name": t.Name, "lua_sha256": t.LuaSHA256})
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
		return
	}
	t, err := s.services.RuleTemplates.Get(r.Context(), device.TenantID, name)
	if errors.Is(err, service.ErrTemplateName) {
		http.Error(w, "invalid template", http.StatusBadRequest)
		return
	}
	if errors.Is(err, service.ErrTemplateNotFound) {
		http.Error(w, "template not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("rule.template.load_failed", "device", device.DeviceID, "err", err)
		http.Error(w, "template load failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"name": t.Name, "lua_sha256": t.LuaSHA256, "workspace": t.Workspace,
	})
}

// handleAdminRuleTemplatesPOST saves the posted workspace under name.
// in: writer, POST JSON. out: JSON or 400.
func (s *Server) handleAdminRuleTemplatesPOST(w http.ResponseWriter, r *http.Request) {
	device, ok := s.adminDeviceFromPath(w, r)
	if !ok {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRuleWorkspaceBody)
	var req ruleTemplateSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	sha, err := s.services.RuleTemplates.Save(r.Context(), device.TenantID, req.Name, req.WorkspaceJSON, req.LuaContent)
	if err != nil {
		if errors.Is(err, service.ErrTemplateName) || errors.Is(err, service.ErrTemplateWorkspace) {
			http.Error(w, "invalid template", http.StatusBadRequest)
			return
		}
		slog.Error("rule.template.save_failed", "device", device.DeviceID, "err", err)
		http.Error(w, "template save failed", http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), authmw.CurrentUser(r), authz.RuleTemplateSave, service.AuditEntry{
		TargetType: "rule_template", TargetID: strings.TrimSpace(req.Name), TenantID: device.TenantID,
		Detail: map[string]any{"lua_sha256": sha},
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "name": strings.TrimSpace(req.Name), "lua_sha256": sha})
}

// handleAdminRuleTemplatesDELETE removes one template by name.
// in: writer, DELETE ?name=. out: JSON or 404.
func (s *Server) handleAdminRuleTemplatesDELETE(w http.ResponseWriter, r *http.Request) {
	device, ok := s.adminDeviceFromPath(w, r)
	if !ok {
		return
	}
	err := s.services.RuleTemplates.Delete(r.Context(), device.TenantID, r.URL.Query().Get("name"))
	if errors.Is(err, service.ErrTemplateName) {
		http.Error(w, "invalid template", http.StatusBadRequest)
		return
	}
	if errors.Is(err, service.ErrTemplateNotFound) {
		http.Error(w, "template not found", http.StatusNotFound)
		return
	}
	if err != nil {
		slog.Error("rule.template.delete_failed", "device", device.DeviceID, "err", err)
		http.Error(w, "template delete failed", http.StatusInternalServerError)
		return
	}
	s.audit(r.Context(), authmw.CurrentUser(r), authz.RuleTemplateDelete, service.AuditEntry{
		TargetType: "rule_template", TargetID: r.URL.Query().Get("name"), TenantID: device.TenantID,
	})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
}

// adminDeviceFromPath resolves the {id} path param to a device for
// super-admin handlers. Writes 4xx/5xx and returns ok=false on failure.
func (s *Server) adminDeviceFromPath(w http.ResponseWriter, r *http.Request) (*service.Device, bool) {
	idStr := r.PathValue("id")
	id, err := uuid.Parse(idStr)
	if err != nil {
		http.Error(w, "bad device id", http.StatusBadRequest)
		return nil, false
	}
	device, err := s.services.Devices.GetByIDAny(r.Context(), id)
	if err != nil {
		slog.Error("device lookup failed", "device", id, "err", err)
		http.Error(w, "device lookup failed", http.StatusInternalServerError)
		return nil, false
	}
	if device == nil {
		http.NotFound(w, r)
		return nil, false
	}
	return device, true
}
