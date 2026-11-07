package mqtt

import (
	"errors"
	"testing"
	"time"

	mqttlib "github.com/eclipse/paho.mqtt.golang"
	"github.com/google/uuid"

	"thesada.app/app/pkg/alerts"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/safego/safegotest"
	"thesada.app/app/pkg/ws"
)

// panicBroker is a broker session that panics on first use, standing in for
// any panic on the device-facing CLI path.
type panicBroker struct{ mqttlib.Client }

func (panicBroker) IsConnected() bool { panic("broker session blew up") }

func TestPullDrift_PanicOnTheDevicePullIsRecovered(t *testing.T) {
	log := safegotest.Capture(t)
	c := &Client{c: panicBroker{}}
	c.pullDrift("acme", uuid.New(), "thesada/acme/dev1",
		[]string{"config.json"}, map[string]string{"config.json": "abc"})
	if rec := log.WaitPanic(t, "mqtt.drift_pull"); rec["tenant"] != "acme" {
		t.Fatalf("panic record = %v, want tenant=acme", rec)
	}
}

func TestFinishAlert_DispatchPanicIsRecovered(t *testing.T) {
	log := safegotest.Capture(t)
	// A zero Notifier has no inflight map, so Dispatch panics on its claim.
	c := &Client{hub: ws.New(&config.Config{}), notifier: &alerts.Notifier{}}
	c.finishAlert("acme", "dev1", uuid.New(), 42)
	if rec := log.WaitPanic(t, "mqtt.alert_dispatch"); rec["alert_id"] != float64(42) {
		t.Fatalf("panic record = %v, want alert_id=42", rec)
	}
}

func TestRetryAlertInsert_PanicFreesTheSlotAndKeepsThePayload(t *testing.T) {
	log := safegotest.Capture(t)
	prev := alertInsertRetryDelay
	alertInsertRetryDelay = time.Millisecond
	t.Cleanup(func() { alertInsertRetryDelay = prev })

	// No services: the retried InsertAlert panics on a nil bundle.
	c := &Client{insertRetrySlots: make(chan struct{}, 1)}
	payload := `{"severity":"crit","code":"T1"}`
	c.retryAlertInsert("acme", "dev1", uuid.New(), "crit", "T1", "hot", []byte(payload), errors.New("db blip"))

	if rec := log.WaitPanic(t, "mqtt.alert_insert_retry"); rec["payload"] != payload {
		t.Fatalf("panic record = %v, want the alert payload for replay", rec)
	}
	select {
	case c.insertRetrySlots <- struct{}{}:
	default:
		t.Fatal("retry slot still held after the panic")
	}
}
