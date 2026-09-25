package mqtt

import (
	"errors"
	"fmt"
	"testing"
)

func TestIsDynsecAlreadyExists(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"already exists", errors.New("role already exists"), true},
		{"already has", errors.New("client already has this role"), true},
		{"unrelated", errors.New("connection refused"), false},
		{"wrapped", fmt.Errorf("create role: %w", errors.New("already exists")), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsDynsecAlreadyExists(tt.err); got != tt.want {
				t.Errorf("IsDynsecAlreadyExists() = %v, want %v", got, tt.want)
			}
		})
	}
}
