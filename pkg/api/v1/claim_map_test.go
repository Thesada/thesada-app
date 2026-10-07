package v1

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"thesada.app/app/pkg/service"
)

func TestClaimIntoHTTP(t *testing.T) {
	code, msg := claimIntoHTTP(service.ErrEnrollNotReady)
	if code != http.StatusConflict || msg != "that device has already been claimed" {
		t.Fatalf("already claimed: got %d %q", code, msg)
	}
	code, msg = claimIntoHTTP(service.ErrQuotaDevices)
	if code != http.StatusConflict || msg != "this tenant is at its device cap" {
		t.Fatalf("device cap: got %d %q", code, msg)
	}
	code, msg = claimIntoHTTP(errors.New("db down"))
	if code != http.StatusInternalServerError || msg != "claim failed" {
		t.Fatalf("other: got %d %q", code, msg)
	}
}

func TestClaimDynsecHTTP(t *testing.T) {
	code, msg := claimDynsecHTTP()
	if code != http.StatusBadGateway || msg != "device claimed but broker provisioning failed, retry the claim" {
		t.Fatalf("dynsec: got %d %q", code, msg)
	}
}

func TestWriteClaimFindError(t *testing.T) {
	user := &service.User{ID: uuid.New()}
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"locked", service.ErrEnrollClaimLocked, "too many wrong codes for that device. Restart the unit that finished announcing first, then retry"},
		{"ambiguous", service.ErrEnrollAmbiguous, "more than one device is waiting with that id and code, so this claim was not made. Ask an operator to clear the duplicates"},
		{"missing", service.ErrEnrollNotFound, "no device is waiting with that id and token"},
	}
	s := &Server{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			s.writeClaimFindError(rec, user, "thesada-aabbccddeeff", tc.err)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400", rec.Code)
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			if body["error"] != tc.want {
				t.Fatalf("got %q, want %q", body["error"], tc.want)
			}
		})
	}
}
