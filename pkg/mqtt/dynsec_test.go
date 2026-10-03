package mqtt

import (
	"context"
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

func TestIsDynsecNotFound(t *testing.T) {
	if IsDynsecNotFound(nil) {
		t.Fatal("nil is not a missing object")
	}
	if !IsDynsecNotFound(errors.New("Client not found")) {
		t.Fatal("missing client must count as gone")
	}
	if IsDynsecNotFound(errors.New("connection refused")) {
		t.Fatal("a transport error is not gone")
	}
}

func TestRetryDynsecDelete(t *testing.T) {
	ctx := context.Background()
	var calls int
	err := RetryDynsecDelete(ctx, func(context.Context) error {
		calls++
		if calls < 3 {
			return errors.New("timeout")
		}
		return nil
	})
	if err != nil || calls != 3 {
		t.Fatalf("retry = %v after %d calls, want nil after 3", err, calls)
	}

	calls = 0
	err = RetryDynsecDelete(ctx, func(context.Context) error {
		calls++
		return errors.New("Client not found")
	})
	if err != nil || calls != 1 {
		t.Fatalf("not found = %v after %d calls, want nil after 1", err, calls)
	}

	calls = 0
	err = RetryDynsecDelete(ctx, func(context.Context) error {
		calls++
		return errors.New("connection refused")
	})
	if err == nil || calls != 3 {
		t.Fatalf("exhausted = %v after %d calls, want error after 3", err, calls)
	}
}
