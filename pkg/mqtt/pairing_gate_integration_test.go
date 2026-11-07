//go:build integration

// The cross-tenant pairing gate in onMessage: a second tenant that claims a
// device id the real owner already paired gets a newer certificate, and the
// owner's traffic must still land. A tenant with no certificate for the id
// stays dropped.
//
//	go test -tags integration -run TestBrokerPairingGate ./pkg/mqtt/...
package mqtt

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service/servicetest"
)

func TestBrokerPairingGate_SquattedIDKeepsOwnerIngest(t *testing.T) {
	env := servicetest.Start(t)
	broker := mqtttest.StartMosquitto(t)
	c := startBrokerClient(t, env, broker)
	ctx := context.Background()

	const owner, squat, drift = "gate-owner", "gate-squat", "gate-drift"
	const dev = "thesada-a1b2c3d4e5f6"
	for _, tn := range []string{owner, squat, drift} {
		env.SeedTenant(t, tn)
	}
	if err := env.Services.Tenants.Refresh(); err != nil {
		t.Fatalf("refresh tenant slugs: %v", err)
	}

	// The owner paired first. The squatter claimed the same id into its own
	// tenant later, so its certificate is the newest. The drift tenant has a
	// row for the id (ACL drift) but no certificate.
	pks := map[string]uuid.UUID{}
	now := time.Now()
	for i, tn := range []string{owner, squat, drift} {
		pk, err := env.Services.Devices.Upsert(tn, dev, "", "", "", "thesada/"+tn+"/"+dev)
		if err != nil {
			t.Fatalf("seed device %s: %v", tn, err)
		}
		pks[tn] = pk
		if tn == drift {
			continue
		}
		if err := env.Services.Certificates.IssueWithIdentity(ctx, tn, pk, "serial-"+tn, "cn-"+tn,
			now.Add(-time.Hour), now.Add(time.Hour), "pem", strings.Repeat(string(rune('a'+i)), 64)); err != nil {
			t.Fatalf("issue cert %s: %v", tn, err)
		}
		if i == 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}

	telemetry := func(tn string) int {
		var n int
		if err := env.Super.QueryRow(ctx,
			`SELECT count(*) FROM device_telemetry WHERE device_pk = $1`, pks[tn]).Scan(&n); err != nil {
			t.Fatalf("count telemetry: %v", err)
		}
		return n
	}

	if err := c.PublishRaw("thesada/"+drift+"/"+dev+"/sensor/temp", []byte("21.5"), 1, false); err != nil {
		t.Fatalf("publish drift: %v", err)
	}
	if err := c.PublishRaw("thesada/"+owner+"/"+dev+"/sensor/temp", []byte("21.5"), 1, false); err != nil {
		t.Fatalf("publish owner: %v", err)
	}
	waitFor(t, 10*time.Second, "owner telemetry despite the squatter's newer cert", func() bool {
		return telemetry(owner) > 0
	})
	time.Sleep(500 * time.Millisecond)
	if n := telemetry(drift); n != 0 {
		t.Fatalf("tenant with no certificate for the id ingested %d rows", n)
	}
}
