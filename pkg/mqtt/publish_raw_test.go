package mqtt

import (
	"errors"
	"testing"
	"time"

	mqttlib "github.com/eclipse/paho.mqtt.golang"
)

// stuckToken never completes, like a publish the broker never acknowledges.
// It records the wait it was given.
type stuckToken struct {
	mqttlib.Token
	waited *time.Duration
}

func (s stuckToken) WaitTimeout(d time.Duration) bool { *s.waited = d; return false }
func (stuckToken) Error() error                       { return nil }

// stuckBroker is connected and hands out tokens that never complete.
type stuckBroker struct {
	mqttlib.Client
	waited time.Duration
}

func (*stuckBroker) IsConnected() bool { return true }
func (b *stuckBroker) Publish(string, byte, bool, interface{}) mqttlib.Token {
	return stuckToken{waited: &b.waited}
}

// A publish the broker never acknowledges is a timeout after publishTimeout, not a success.
func TestPublishRaw_TimeoutIsAnError(t *testing.T) {
	b := &stuckBroker{}
	c := &Client{c: b}
	err := c.PublishRaw("thesada/acme/dev1/cli/ota.check", []byte("{}"), 0, false)
	if !errors.Is(err, ErrPublishTimeout) {
		t.Fatalf("unacknowledged publish = %v, want ErrPublishTimeout", err)
	}
	if b.waited != publishTimeout {
		t.Fatalf("waited %v for the broker, want %v", b.waited, publishTimeout)
	}
}
