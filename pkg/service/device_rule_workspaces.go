// Blockly visual-rules workspace storage. Canonical current state plus
// immutable save history, separate from device_files (which holds the Lua
// bytes the device actually runs after a push).
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// Allowed rule-workspace slots. Matches the CHECK on the table; keep in sync
// with migration 0029. New slots are a follow-up issue, not an open enum.
var allowedRuleSlots = map[string]struct{}{
	"rules.lua": {},
	"main.lua":  {},
}

// DeviceRuleWorkspacesService owns device_rule_workspaces + history.
type DeviceRuleWorkspacesService struct {
	cfg   *config.Config
	pools db.Pools
}

// ValidRuleSlot reports whether slot is one of the closed vocabulary.
// in: slot name. out: true if allowed.
func ValidRuleSlot(slot string) bool {
	_, ok := allowedRuleSlots[slot]
	return ok
}

// Save upserts the canonical workspace for (devicePk, slot) and appends a
// history row when lua_sha256 changes or the operator re-saves. Tenant-scoped
// via WithTenant.
//
// in: ctx, tenantID, devicePk, slot, workspaceJSON, luaContent, source, createdBy
// out: lua sha256 hex, error
func (s *DeviceRuleWorkspacesService) Save(
	ctx context.Context,
	tenantID string,
	devicePk uuid.UUID,
	slot, workspaceJSON, luaContent, source string,
	createdBy *uuid.UUID,
) (string, error) {
	if !ValidRuleSlot(slot) {
		return "", fmt.Errorf("invalid rule slot %q", slot)
	}
	if workspaceJSON == "" {
		return "", errors.New("workspace_json required")
	}
	if source == "" {
		source = "editor"
	}
	sum := sha256.Sum256([]byte(luaContent))
	shaHex := hex.EncodeToString(sum[:])

	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		var prev *string
		err := tx.QueryRow(ctx,
			`SELECT lua_sha256 FROM device_rule_workspaces WHERE device_pk = $1 AND slot = $2`,
			devicePk, slot).Scan(&prev)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		_, err = tx.Exec(ctx,
			`INSERT INTO device_rule_workspaces
			   (device_pk, slot, workspace_json, lua_content, lua_sha256, source, updated_at, updated_by)
			 VALUES ($1, $2, $3, $4, $5, $6, NOW(), $7)
			 ON CONFLICT (device_pk, slot) DO UPDATE
			   SET workspace_json = EXCLUDED.workspace_json,
			       lua_content    = EXCLUDED.lua_content,
			       lua_sha256     = EXCLUDED.lua_sha256,
			       source         = EXCLUDED.source,
			       updated_at     = EXCLUDED.updated_at,
			       updated_by     = EXCLUDED.updated_by`,
			devicePk, slot, workspaceJSON, luaContent, shaHex, source, createdBy)
		if err != nil {
			return err
		}

		// One history row per save so a bad rule can roll back to the prior
		// generated Lua (issue #38 open question, leaning yes).
		_, err = tx.Exec(ctx,
			`INSERT INTO device_rule_workspace_history
			   (device_pk, slot, workspace_json, lua_content, lua_sha256, prev_sha256, source, created_by, created_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
			devicePk, slot, workspaceJSON, luaContent, shaHex, prev, source, createdBy)
		return err
	})
	if err != nil {
		return "", err
	}
	return shaHex, nil
}

// Latest returns the canonical workspace for (devicePk, slot), or nil when
// none has been saved yet. Tenant-scoped via WithTenant.
//
// in: ctx, tenantID, devicePk, slot
// out: *DeviceRuleWorkspace or nil; error on DB fault
func (s *DeviceRuleWorkspacesService) Latest(ctx context.Context, tenantID string, devicePk uuid.UUID, slot string) (*DeviceRuleWorkspace, error) {
	if !ValidRuleSlot(slot) {
		return nil, fmt.Errorf("invalid rule slot %q", slot)
	}
	const q = `
		SELECT device_pk, slot, workspace_json, lua_content, lua_sha256, source, updated_at, updated_by
		FROM device_rule_workspaces
		WHERE device_pk = $1 AND slot = $2`
	var w DeviceRuleWorkspace
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, q, devicePk, slot).Scan(
			&w.DevicePK, &w.Slot, &w.WorkspaceJSON, &w.LuaContent, &w.LuaSHA256,
			&w.Source, &w.UpdatedAt, &w.UpdatedBy)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &w, nil
}

// History returns the newest-first save history for (devicePk, slot).
// in: ctx, tenantID, devicePk, slot, limit
// out: history rows
func (s *DeviceRuleWorkspacesService) History(ctx context.Context, tenantID string, devicePk uuid.UUID, slot string, limit int) ([]DeviceRuleWorkspaceHistory, error) {
	if !ValidRuleSlot(slot) {
		return nil, fmt.Errorf("invalid rule slot %q", slot)
	}
	if limit <= 0 {
		limit = 50
	}
	if limit > 250 {
		limit = 250
	}
	const q = `
		SELECT id, device_pk, slot, workspace_json, lua_content, lua_sha256, prev_sha256, source, created_by, created_at
		FROM device_rule_workspace_history
		WHERE device_pk = $1 AND slot = $2
		ORDER BY created_at DESC
		LIMIT $3`
	var out []DeviceRuleWorkspaceHistory
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q, devicePk, slot, limit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h DeviceRuleWorkspaceHistory
			if err := rows.Scan(
				&h.ID, &h.DevicePK, &h.Slot, &h.WorkspaceJSON, &h.LuaContent,
				&h.LuaSHA256, &h.PrevSHA256, &h.Source, &h.CreatedBy, &h.CreatedAt,
			); err != nil {
				return err
			}
			out = append(out, h)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
