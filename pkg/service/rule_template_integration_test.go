//go:build integration

package service_test

import (
	"context"
	"errors"
	"testing"

	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
)

// TestRuleTemplate_TenantCannotReadAnotherTenantsName checks RLS on the template table.
// in: t. out: none.
func TestRuleTemplate_TenantCannotReadAnotherTenantsName(t *testing.T) {
	env := servicetest.Start(t)
	ctx := context.Background()
	env.SeedTenant(t, "tmpl-a")
	env.SeedTenant(t, "tmpl-b")
	tpl := env.Services.RuleTemplates

	if _, err := tpl.Save(ctx, "tmpl-a", "Boiler", `{"blocks":true}`, "return 1"); err != nil {
		t.Fatal(err)
	}
	got, err := tpl.Get(ctx, "tmpl-a", "Boiler")
	if err != nil || got.Workspace != `{"blocks":true}` {
		t.Fatalf("owner get = %+v err=%v", got, err)
	}
	list, err := tpl.List(ctx, "tmpl-a")
	if err != nil || len(list) != 1 || list[0].Name != "Boiler" {
		t.Fatalf("owner list = %+v err=%v", list, err)
	}
	if _, err := tpl.Get(ctx, "tmpl-b", "Boiler"); !errors.Is(err, service.ErrTemplateNotFound) {
		t.Fatalf("other tenant get = %v, want not found", err)
	}
	if list, err := tpl.List(ctx, "tmpl-b"); err != nil || len(list) != 0 {
		t.Fatalf("other tenant list = %+v err=%v", list, err)
	}
	if err := tpl.Delete(ctx, "tmpl-b", "Boiler"); !errors.Is(err, service.ErrTemplateNotFound) {
		t.Fatalf("other tenant delete = %v, want not found", err)
	}
	if err := tpl.Delete(ctx, "tmpl-a", "Boiler"); err != nil {
		t.Fatal(err)
	}
	if _, err := tpl.Get(ctx, "tmpl-a", "Boiler"); !errors.Is(err, service.ErrTemplateNotFound) {
		t.Fatalf("deleted get = %v", err)
	}
}
