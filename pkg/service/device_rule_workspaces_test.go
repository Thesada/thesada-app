package service

import "testing"

func TestValidRuleSlot(t *testing.T) {
	cases := []struct {
		slot string
		want bool
	}{
		{"rules.lua", true},
		{"main.lua", true},
		{"", false},
		{"other.lua", false},
		{"/scripts/rules.lua", false},
		{"RULES.LUA", false},
	}
	for _, tc := range cases {
		if got := ValidRuleSlot(tc.slot); got != tc.want {
			t.Errorf("ValidRuleSlot(%q) = %v, want %v", tc.slot, got, tc.want)
		}
	}
}

func TestNormalizeRuleSlot(t *testing.T) {
	cases := []struct {
		slot string
		want string
	}{
		{"", DefaultRuleSlot},
		{"rules.lua", "rules.lua"},
		{"main.lua", "main.lua"},
		{"other.lua", "other.lua"},
	}
	for _, tc := range cases {
		if got := NormalizeRuleSlot(tc.slot); got != tc.want {
			t.Errorf("NormalizeRuleSlot(%q) = %q, want %q", tc.slot, got, tc.want)
		}
	}
}
