package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// ValidTemplateName reports whether name is a short single-line label.
// in: name. out: true when it can be stored.
func ValidTemplateName(name string) bool {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 80 {
		return false
	}
	return !strings.ContainsAny(name, "\n\r")
}

// RuleTemplate is one named Blockly workspace for a tenant.
type RuleTemplate struct {
	Name      string
	LuaSHA256 string
	Workspace string
}

// RuleTemplateService stores named workspaces in rule_templates.
type RuleTemplateService struct {
	pools db.Pools
}

// ErrTemplateNotFound is returned when the name is not in this tenant.
var ErrTemplateNotFound = errors.New("template not found")

// ErrTemplateName means the label is blank, too long, or contains a newline.
var ErrTemplateName = errors.New("invalid template name")

// ErrTemplateWorkspace means Save was called without workspace JSON.
var ErrTemplateWorkspace = errors.New("workspace required")

// List returns template names and hashes in name order, capped at 50.
// in: ctx, tenant id. out: templates, error.
func (s *RuleTemplateService) List(ctx context.Context, tenantID string) ([]RuleTemplate, error) {
	const query = `
		SELECT name, lua_sha256
		FROM rule_templates
		ORDER BY name
		LIMIT 50`
	var out []RuleTemplate
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, query)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var t RuleTemplate
			if err := rows.Scan(&t.Name, &t.LuaSHA256); err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("rule template list: %w", err)
	}
	return out, nil
}

// Get returns one template including its workspace JSON.
// in: ctx, tenant id, name. out: template, error.
func (s *RuleTemplateService) Get(ctx context.Context, tenantID, name string) (*RuleTemplate, error) {
	name = strings.TrimSpace(name)
	if !ValidTemplateName(name) {
		return nil, ErrTemplateName
	}
	const query = `
		SELECT name, lua_sha256, workspace
		FROM rule_templates
		WHERE name = $1`
	var t RuleTemplate
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, query, name).Scan(&t.Name, &t.LuaSHA256, &t.Workspace)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrTemplateNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("rule template get: %w", err)
	}
	return &t, nil
}

// Save upserts a template by name. The stored hash is sha256 of luaContent.
// in: ctx, tenant id, name, workspace JSON, lua. out: lua hash, error.
func (s *RuleTemplateService) Save(ctx context.Context, tenantID, name, workspace, luaContent string) (string, error) {
	name = strings.TrimSpace(name)
	if !ValidTemplateName(name) {
		return "", ErrTemplateName
	}
	if workspace == "" {
		return "", ErrTemplateWorkspace
	}
	sum := sha256.Sum256([]byte(luaContent))
	shaHex := hex.EncodeToString(sum[:])
	const query = `
		INSERT INTO rule_templates (tenant_id, name, lua_sha256, workspace)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, name) DO UPDATE
		SET lua_sha256 = EXCLUDED.lua_sha256,
		    workspace = EXCLUDED.workspace`
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, query, tenantID, name, shaHex, workspace)
		return err
	})
	if err != nil {
		return "", fmt.Errorf("rule template save: %w", err)
	}
	return shaHex, nil
}

// Delete removes a template by name. Missing names return ErrTemplateNotFound.
// in: ctx, tenant id, name. out: error.
func (s *RuleTemplateService) Delete(ctx context.Context, tenantID, name string) error {
	name = strings.TrimSpace(name)
	if !ValidTemplateName(name) {
		return ErrTemplateName
	}
	const query = `DELETE FROM rule_templates WHERE name = $1`
	var n int64
	err := db.WithTenant(ctx, s.pools.App, tenantID, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, query, name)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return nil
	})
	if err != nil {
		return fmt.Errorf("rule template delete: %w", err)
	}
	if n == 0 {
		return ErrTemplateNotFound
	}
	return nil
}
