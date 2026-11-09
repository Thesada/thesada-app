//go:build integration

// Broker identity against a mosquitto with dynamic security: a reassigned
// device's client and role are named after the tenant they were issued under,
// and every teardown and re-issue has to find them there.
//
//	go test -tags integration -run TestBrokerIdentity ./pkg/web/...
package web

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/alerts"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/mqtt/mqtttest"
	"thesada.app/app/pkg/service"
	"thesada.app/app/pkg/service/servicetest"
	"thesada.app/app/pkg/ws"
)

const (
	biFrom  = "bi-from"
	biTo    = "bi-to"
	biDevID = "thesada-0e0e0e0e0e0e"
)

// biFixture is a server on a dynsec broker and one device provisioned in
// biFrom, then reassigned to biTo.
type biFixture struct {
	env    *servicetest.Env
	s      *Server
	device *service.Device
}

// startBrokerIdentity provisions the device's identity under biFrom and moves it.
func startBrokerIdentity(t *testing.T) biFixture {
	t.Helper()
	env := servicetest.Start(t)
	cfg := *env.Cfg
	cfg.MQTTBrokerURL = mqtttest.StartMosquittoDynsec(t)
	cfg.MQTTClientID = "broker-identity-test"
	cfg.MQTTTopicRoot = "thesada"
	cfg.MQTTUsername, cfg.MQTTPassword = mqtttest.DynsecAdminUser, mqtttest.DynsecAdminPassword
	client, err := mqtt.Start(context.Background(), &cfg, env.Pools.App,
		alerts.New(&cfg, env.Pools, nil), ws.New(&cfg), env.Services)
	if err != nil {
		t.Fatalf("mqtt start: %v", err)
	}
	t.Cleanup(client.Stop)
	deadline := time.Now().Add(30 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := client.DynsecClientEnabled(ctx, mqtttest.DynsecAdminUser)
		cancel()
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("dynsec never answered: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
	s := &Server{cfg: &cfg, services: env.Services, mqtt: client, jobs: newRequestStore[jobResult](time.Minute, t.Context().Done())}

	ctx := context.Background()
	env.SeedTenant(t, biFrom)
	env.SeedTenant(t, biTo)
	pk, err := env.Services.Devices.Upsert(biFrom, biDevID, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if step, err := s.provisionDeviceDynsec(ctx, biFrom, biDevID,
		service.DeviceTopicPrefix("thesada", biFrom, biDevID), service.DeviceCertCN(biFrom, biDevID)); err != nil {
		t.Fatalf("provision in %s: %s: %v", biFrom, step, err)
	}
	if !clientExists(t, s, service.DeviceCertCN(biFrom, biDevID)) {
		t.Fatal("provisioning left no client")
	}
	if err := env.Services.Devices.Reassign(ctx, pk, biTo); err != nil {
		t.Fatal(err)
	}
	return biFixture{env: env, s: s, device: deviceByID(t, env, pk)}
}

// deviceByID reloads a device row.
func deviceByID(t *testing.T, env *servicetest.Env, pk uuid.UUID) *service.Device {
	t.Helper()
	d, err := env.Services.Devices.GetByIDAny(context.Background(), pk)
	if err != nil || d == nil {
		t.Fatalf("load device %s: %v", pk, err)
	}
	return d
}

// clientExists asks the broker for a dynsec client.
func clientExists(t *testing.T, s *Server, name string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.mqtt.DynsecClientEnabled(ctx, name)
	if err != nil && strings.Contains(err.Error(), "not found") {
		return false
	}
	if err != nil {
		t.Fatalf("getClient %s: %v", name, err)
	}
	return true
}

// roleGone deletes a role that should already be gone and reports whether the
// broker said it never had it.
func roleGone(t *testing.T, s *Server, name string) bool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := s.mqtt.DeleteDynsecRole(ctx, name)
	return err != nil && strings.Contains(err.Error(), "not found")
}

// assertNoIdentity checks no client or role is left under either tenant.
func assertNoIdentity(t *testing.T, f biFixture) {
	t.Helper()
	for _, tn := range []string{biFrom, biTo} {
		if clientExists(t, f.s, service.DeviceCertCN(tn, biDevID)) {
			t.Errorf("client %s still on the broker", service.DeviceCertCN(tn, biDevID))
		}
	}
	if !roleGone(t, f.s, dynsecDeviceRoleName(biFrom, biDevID)) {
		t.Errorf("role %s was still on the broker", dynsecDeviceRoleName(biFrom, biDevID))
	}
}

// Delete in the new tenant removes the identity issued in the old one.
func TestBrokerIdentity_DeleteAfterReassignRemovesTheIssuedIdentity(t *testing.T) {
	f := startBrokerIdentity(t)
	verdict, brokerClean := f.s.cascadeDeleteOne(context.Background(), "bulk delete", "op@example.com",
		f.device, recoveryVerdict{usable: true}, true)
	if verdict != cascadeOK || !brokerClean {
		t.Fatalf("cascade = %v, broker clean %v", verdict, brokerClean)
	}
	assertNoIdentity(t, f)
}

// A revoke keeps the row, so the record is cleared with the identity.
func TestBrokerIdentity_RevokeAfterReassignRemovesTheIssuedIdentity(t *testing.T) {
	f := startBrokerIdentity(t)
	if !f.s.teardownDeviceDynsec(context.Background(), f.device, "admin_revoke") {
		t.Fatal("teardown reported a live client")
	}
	assertNoIdentity(t, f)
	id, err := f.env.Services.Devices.BrokerIdentityOf(context.Background(), deviceByID(t, f.env, f.device.ID))
	if err != nil || id.Current != biTo || len(id.Stale) != 0 {
		t.Fatalf("identity after revoke = %+v, %v, want the record cleared (falls back to %s)", id, err, biTo)
	}
}

// A lookup that fails deletes nothing and reports the client as possibly live.
func TestBrokerIdentity_FailedLookupFailsTheTeardown(t *testing.T) {
	f := startBrokerIdentity(t)
	broken := servicetest.OpenAs(t, f.env.BaseURL, "thesada_app_admin")
	broken.Close()
	services, err := service.New(f.s.cfg, db.Pools{App: f.env.Pools.App, Admin: broken})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: f.s.cfg, services: services, mqtt: f.s.mqtt, jobs: newRequestStore[jobResult](time.Minute, t.Context().Done())}
	if s.teardownDeviceDynsec(context.Background(), f.device, "device_delete") {
		t.Fatal("teardown with a failed lookup reported clean")
	}
	if !clientExists(t, f.s, service.DeviceCertCN(biFrom, biDevID)) {
		t.Fatal("teardown with a failed lookup deleted the client anyway")
	}
}

// A re-issue whose broker write fails keeps the old identity recorded, so a
// later teardown still deletes it.
func TestBrokerIdentity_FailedReissueKeepsTheOldIdentity(t *testing.T) {
	f := startBrokerIdentity(t)
	offline := &Server{cfg: f.s.cfg, services: f.env.Services, mqtt: &mqtt.Client{}, jobs: newRequestStore[jobResult](time.Minute, t.Context().Done())}
	if _, err := offline.provisionDeviceDynsec(context.Background(), biTo, biDevID,
		service.DeviceTopicPrefix("thesada", biTo, biDevID), service.DeviceCertCN(biTo, biDevID)); err == nil {
		t.Fatal("provision on a disconnected broker succeeded")
	}
	if !f.s.teardownDeviceDynsec(context.Background(), deviceByID(t, f.env, f.device.ID), "device_delete") {
		t.Fatal("teardown reported a live client")
	}
	assertNoIdentity(t, f)
}

// Re-pairing in the new tenant issues there and removes the old identity.
func TestBrokerIdentity_ReprovisionUnderTheNewTenantRemovesTheOld(t *testing.T) {
	f := startBrokerIdentity(t)
	if step, err := f.s.provisionDeviceDynsec(context.Background(), biTo, biDevID,
		service.DeviceTopicPrefix("thesada", biTo, biDevID), service.DeviceCertCN(biTo, biDevID)); err != nil {
		t.Fatalf("re-provision: %s: %v", step, err)
	}
	if !clientExists(t, f.s, service.DeviceCertCN(biTo, biDevID)) {
		t.Fatal("re-provision left no client under the new tenant")
	}
	if clientExists(t, f.s, service.DeviceCertCN(biFrom, biDevID)) {
		t.Fatal("re-provision left the old tenant's client live")
	}
	if !roleGone(t, f.s, dynsecDeviceRoleName(biFrom, biDevID)) {
		t.Fatal("re-provision left the old tenant's role")
	}
}

// A second row in the old tenant cannot be provisioned onto the unit's
// identity, and its teardown leaves the unit's client alone.
func TestBrokerIdentity_PhantomRowGetsNoIdentity(t *testing.T) {
	f := startBrokerIdentity(t)
	ctx := context.Background()
	phantomPk, err := f.env.Services.Devices.Upsert(biFrom, biDevID, "", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	step, err := f.s.provisionDeviceDynsec(ctx, biFrom, biDevID,
		service.DeviceTopicPrefix("thesada", biFrom, biDevID), service.DeviceCertCN(biFrom, biDevID))
	if !errors.Is(err, service.ErrBrokerIdentityTaken) || step != "broker_identity_reserve" {
		t.Fatalf("provision for the phantom = %s: %v, want broker_identity_reserve: ErrBrokerIdentityTaken", step, err)
	}
	if !f.s.teardownDeviceDynsec(ctx, deviceByID(t, f.env, phantomPk), "device_delete") {
		t.Fatal("phantom teardown reported a live client")
	}
	if !clientExists(t, f.s, service.DeviceCertCN(biFrom, biDevID)) {
		t.Fatal("the phantom's teardown deleted the reassigned unit's client")
	}
}
