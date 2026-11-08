package mqtt

import (
	"testing"
	"time"

	mqttlib "github.com/eclipse/paho.mqtt.golang"
)

// stuckToken never completes, like a publish the broker never acknowledges.
type stuckToken struct{ mqttlib.Token }

func (stuckToken) WaitTimeout(time.Duration) bool { return false }
func (stuckToken) Error() error                   { return nil }

// stuckBroker is connected and hands out tokens that never complete.
type stuckBroker struct{ mqttlib.Client }

func (stuckBroker) IsConnected() bool { return true }
func (stuckBroker) Publish(string, byte, bool, interface{}) mqttlib.Token {
	return stuckToken{}
}

// A publish the broker never acknowledges is an error, not a success.
func TestPublishRaw_TimeoutIsAnError(t *testing.T) {
	c := &Client{c: stuckBroker{}}
	if err := c.PublishRaw("thesada/acme/dev1/cli/ota.check", []byte("{}"), 0, false); err == nil {
		t.Fatal("unacknowledged publish reported success")
	}
}
