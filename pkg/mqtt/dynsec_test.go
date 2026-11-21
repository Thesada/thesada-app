package mqtt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
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

// Replies to other callers' commands share the response topic. They must not
// fill the waiter's buffer and push its own reply out.
func TestSendDynsec_ForeignRepliesDoNotCrowdOutOurs(t *testing.T) {
	c := &Client{}
	c.c = &answerBroker{answer: func(_ string, p []byte) {
		var env dynsecEnvelope
		if err := json.Unmarshal(p, &env); err != nil || len(env.Commands) != 1 {
			t.Errorf("command envelope %q: %v", p, err)
			return
		}
		for _, id := range []string{"other-1", "other-2", env.Commands[0].CorrelationData} {
			resp := fmt.Sprintf(`{"responses":[{"command":"createRole","correlationData":%q}]}`, id)
			c.fanoutTaps(dynsecResponseTopic, []byte(resp), false, 0)
		}
	}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.CreateDynsecRole(ctx, "role", nil); err != nil {
		t.Fatalf("our reply arrived after two foreign ones, got %v", err)
	}
}
