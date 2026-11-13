package mqtt

import (
	"time"

	mqttlib "github.com/eclipse/paho.mqtt.golang"
)

// doneToken is a publish the broker acknowledged at once.
type doneToken struct{ mqttlib.Token }

func (doneToken) WaitTimeout(time.Duration) bool { return true }
func (doneToken) Error() error                   { return nil }

// answerBroker is connected, acknowledges every publish and runs answer on it
// before Publish returns, the way a fast broker and device would reply.
type answerBroker struct {
	mqttlib.Client
	answer func(topic string, payload []byte)
}

func (*answerBroker) IsConnected() bool { return true }
func (b *answerBroker) Publish(topic string, _ byte, _ bool, p interface{}) mqttlib.Token {
	if b.answer != nil {
		b.answer(topic, p.([]byte))
	}
	return doneToken{}
}
