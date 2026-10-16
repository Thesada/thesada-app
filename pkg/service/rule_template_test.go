package service

import (
	"context"
	"errors"
	"testing"
)

func TestValidTemplateName_AcceptsAShortLabelAndRejectsBlank(t *testing.T) {
	if !ValidTemplateName("Boiler high") {
		t.Fatal("plain name rejected")
	}
	if ValidTemplateName("  ") || ValidTemplateName("a\nb") {
		t.Fatal("blank or newline accepted")
	}
}

func TestRuleTemplate_BadNameIsNotMissing(t *testing.T) {
	s := &RuleTemplateService{}
	ctx := context.Background()
	if _, err := s.Get(ctx, "t", "bad\nname"); !errors.Is(err, ErrTemplateName) {
		t.Fatalf("get = %v, want ErrTemplateName", err)
	}
	if err := s.Delete(ctx, "t", " "); !errors.Is(err, ErrTemplateName) {
		t.Fatalf("delete = %v, want ErrTemplateName", err)
	}
	if _, err := s.Save(ctx, "t", "ok", "", "lua"); !errors.Is(err, ErrTemplateWorkspace) {
		t.Fatalf("save = %v, want ErrTemplateWorkspace", err)
	}
}
