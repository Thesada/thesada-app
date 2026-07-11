// Contracts for the health endpoints: /healthz is liveness and never fails
// on component outages (a 503 there would restart-loop the container for an
// infra blip); /readyz carries the gating signal for DB and broker.
package v1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// probeServer builds a Server with only the health probes wired.
func probeServer(dbErr error, broker string) *Server {
	s := &Server{mux: http.NewServeMux()}
	s.routes()
	s.SetHealthProbes(
		func(context.Context) error { return dbErr },
		func() string { return broker },
	)
	return s
}

func get(t *testing.T, s *Server, path string) (int, map[string]string) {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("parse %s body: %v", path, err)
	}
	return rec.Code, body
}

func TestHealthz_Always200EvenWithEverythingDown(t *testing.T) {
	s := probeServer(errors.New("db down"), "down")
	code, body := get(t, s, "/healthz")
	if code != http.StatusOK {
		t.Fatalf("healthz = %d, want 200 (liveness must not gate on components)", code)
	}
	if body["db"] != "down" || body["mqtt"] != "down" {
		t.Fatalf("healthz body = %v, want component detail down/down", body)
	}
}

func TestReadyz_Returns503WhenBrokerDown(t *testing.T) {
	s := probeServer(nil, "down")
	code, body := get(t, s, "/readyz")
	if code != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d, want 503 on broker outage", code)
	}
	if body["status"] != "degraded" {
		t.Fatalf("readyz status = %q, want degraded", body["status"])
	}
}

func TestReadyz_Returns503WhenDBDown(t *testing.T) {
	s := probeServer(errors.New("no route"), "up")
	if code, _ := get(t, s, "/readyz"); code != http.StatusServiceUnavailable {
		t.Fatalf("readyz = %d, want 503 on db outage", code)
	}
}

func TestReadyz_DisabledBrokerDoesNotFailReadiness(t *testing.T) {
	s := probeServer(nil, "disabled")
	if code, _ := get(t, s, "/readyz"); code != http.StatusOK {
		t.Fatalf("readyz = %d, want 200 when broker deliberately disabled", code)
	}
}

func TestReadyz_UnwiredProbesReportUnknownButReady(t *testing.T) {
	s := &Server{mux: http.NewServeMux()}
	s.routes()
	code, body := get(t, s, "/readyz")
	if code != http.StatusOK || body["db"] != "unknown" {
		t.Fatalf("readyz = %d %v, want 200 with unknown components", code, body)
	}
}
