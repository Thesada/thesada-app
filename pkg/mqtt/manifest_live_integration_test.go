//go:build integration

// The retained_topics manifest reaches a running app as a live delivery (the
// broker forwards with retain=0), so it must be cached on both paths.
//
//	go test -tags integration -run TestOnMessage_RetainedManifest ./pkg/mqtt/...
package mqtt

import (
	"testing"

	mqttlib "github.com/eclipse/paho.mqtt.golang"

	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/ws"
)

type fakeMsg struct {
	mqttlib.Message
	topic    string
	payload  []byte
	retained bool
}

func (m fakeMsg) Topic() string   { return m.topic }
func (m fakeMsg) Payload() []byte { return m.payload }
func (m fakeMsg) Retained() bool  { return m.retained }
func (fakeMsg) Qos() byte         { return 0 }

func TestOnMessage_RetainedManifestCachedLiveAndRetained(t *testing.T) {
	env := servicetest.Start(t)
	const tenant = "manifest-live"
	env.SeedTenant(t, tenant)
	if err := env.Services.Tenants.Refresh(); err != nil {
		t.Fatalf("refresh tenant slugs: %v", err)
	}
	c := &Client{services: env.Services, hub: ws.New(env.Cfg)}

	for _, retained := range []bool{false, true} {
		prefix := "thesada/" + tenant + "/live"
		if retained {
			prefix = "thesada/" + tenant + "/replay"
		}
		c.onMessage(nil, fakeMsg{
			topic:    prefix + "/info/retained_topics",
			payload:  []byte(`["` + prefix + `/status"]`),
			retained: retained,
		})
		if got := c.GetRetainedManifest(prefix); len(got) != 1 || got[0] != prefix+"/status" {
			t.Fatalf("retained=%v: cached manifest = %v, want [%s/status]", retained, got, prefix)
		}
	}

	// The broker forwards a retained delete to live subscribers as an empty
	// live message. It clears the cache.
	prefix := "thesada/" + tenant + "/live"
	c.onMessage(nil, fakeMsg{topic: prefix + "/info/retained_topics"})
	if got := c.GetRetainedManifest(prefix); got != nil {
		t.Fatalf("empty live manifest left %v cached", got)
	}
}
