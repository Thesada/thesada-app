//go:build integration

// The device delete refusals against a real DB: an unknown id 404s and a
// wrong confirmation redirects with the confirm flash, both leaving the
// device row in place.
//
//	go test -tags integration -run TestAdminDeviceDelete ./pkg/web/...
package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service/servicetest"
)

func TestAdminDeviceDelete_RefusalsKeepTheDevice(t *testing.T) {
	env := servicetest.Start(t)
	s := &Server{cfg: env.Cfg, services: env.Services}
	const tenant = "del-t"
	env.SeedTenant(t, tenant)
	pk, err := env.Services.Devices.Upsert(tenant, "del-dev", "", "", "", "thesada/"+tenant+"/del-dev")
	if err != nil {
		t.Fatal(err)
	}
	post := func(id, confirm string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(url.Values{"confirm_device_id": {confirm}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetPathValue("id", id)
		rec := httptest.NewRecorder()
		s.handleAdminDeviceDelete(rec, req)
		return rec
	}
	stillThere := func(t *testing.T) {
		t.Helper()
		d, err := env.Services.Devices.GetByIDAny(context.Background(), pk)
		if err != nil || d == nil {
			t.Fatalf("device gone after a refused delete: %v", err)
		}
	}

	t.Run("unknown device 404s", func(t *testing.T) {
		if rec := post(uuid.NewString(), "del-dev"); rec.Code != http.StatusNotFound {
			t.Fatalf("status = %d, want 404", rec.Code)
		}
		stillThere(t)
	})
	t.Run("wrong confirmation redirects and keeps the device", func(t *testing.T) {
		rec := post(pk.String(), "not-the-id")
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != flashAdminConfirmDevice.on("/admin/devices") {
			t.Fatalf("got %d %s, want the confirm flash", rec.Code, rec.Header().Get("Location"))
		}
		stillThere(t)
	})
}
