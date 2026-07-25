package alerts

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"thesada.app/app/pkg/config"
)

func TestRetryBackoff_DoublesPerAttemptAndCaps(t *testing.T) {
	base := time.Minute
	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{0, time.Minute}, // defensive: pre-first-attempt input clamps to base
		{1, time.Minute},
		{2, 2 * time.Minute},
		{3, 4 * time.Minute},
		{5, 16 * time.Minute},
		{7, 64 * time.Minute},
		{50, 64 * time.Minute}, // cap: a runaway attempt count never overflows
	}
	for _, c := range cases {
		if got := retryBackoff(base, c.attempts); got != c.want {
			t.Errorf("retryBackoff(1m, %d) = %v, want %v", c.attempts, got, c.want)
		}
	}
}

// roundTripFunc lets a test stand in for the Telegram transport.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestSendTelegram_TransportErrorNeverLeaksToken(t *testing.T) {
	const token = "8123456:AAHsecretsecretsecret"
	n := &Notifier{
		cfg: &config.Config{TelegramBotToken: token},
		http: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			// http.Client wraps this in *url.Error, whose text includes the
			// full request URL - the exact leak path under test.
			return nil, errors.New("dial tcp 149.154.167.220:443: connect: connection refused")
		})},
	}
	err := n.sendTelegram(context.Background(), "42", "hello")
	if err == nil {
		t.Fatal("want transport error, got nil")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("bot token leaked into error: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("token not masked, error: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("underlying cause lost, error: %q", err.Error())
	}
}

func TestRedactToken_PassthroughWhenNoToken(t *testing.T) {
	base := errors.New("plain failure")
	if got := redactToken(base, ""); got != base {
		t.Errorf("empty token: want passthrough, got %v", got)
	}
	if got := redactToken(base, "tok"); got != base {
		t.Errorf("token absent from text: want passthrough, got %v", got)
	}
	if got := redactToken(nil, "tok"); got != nil {
		t.Errorf("nil error: want nil, got %v", got)
	}
}
