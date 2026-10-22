package alerts

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSendWebhook_BodyCarriesTheAlertFields(t *testing.T) {
	var gotBody, gotType string
	n := &Notifier{webhookHTTP: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		gotType = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		return &http.Response{StatusCode: 204, Body: io.NopCloser(strings.NewReader("")), Header: make(http.Header)}, nil
	})}}
	code := "absence"
	row := &alertRow{
		severity:   "warn",
		code:       &code,
		message:    "no contact",
		receivedAt: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC),
		deviceID:   "pump",
	}
	payload, err := webhookPayload(7, row)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.sendWebhook(context.Background(), "https://hooks.example/alert", payload); err != nil {
		t.Fatal(err)
	}
	if gotType != "application/json" {
		t.Fatalf("content-type %q", gotType)
	}
	for _, want := range []string{`"alert_id":7`, `"device_id":"pump"`, `"code":"absence"`} {
		if !strings.Contains(gotBody, want) {
			t.Fatalf("body %s missing %s", gotBody, want)
		}
	}
}

func TestWebhookErr_DropsTheDestination(t *testing.T) {
	inner := errors.New("connection refused")
	got := webhookErr(&url.Error{Op: "Post", URL: "https://hooks.example/secret-token", Err: inner})
	if !errors.Is(got, inner) || strings.Contains(got.Error(), "secret-token") {
		t.Fatalf("err = %v", got)
	}
}

func TestWebhookPayload_IncludesCodeWhenUnset(t *testing.T) {
	row := &alertRow{
		severity:   "warn",
		message:    "no contact",
		receivedAt: time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC),
		deviceID:   "pump",
	}
	payload, err := webhookPayload(7, row)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"code":""`) {
		t.Fatalf("body %s dropped code", payload)
	}
}

func TestSendWebhook_RefusesLoopbackAndRedirect(t *testing.T) {
	n := &Notifier{webhookHTTP: newWebhookClient(nil)}
	if err := n.sendWebhook(context.Background(), "http://127.0.0.1/hook", []byte("{}")); err == nil {
		t.Fatal("loopback was posted")
	}
	n.webhookHTTP = &http.Client{
		Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			h := make(http.Header)
			h.Set("Location", "http://127.0.0.1/secret")
			return &http.Response{StatusCode: 302, Header: h, Body: io.NopCloser(strings.NewReader(""))}, nil
		}),
		CheckRedirect: newWebhookClient(nil).CheckRedirect,
	}
	if err := n.sendWebhook(context.Background(), "https://hooks.example/alert", []byte("{}")); err == nil {
		t.Fatal("redirect was followed")
	}
}

// The dial-time check refuses a private target unless the operator listed it,
// so a host name that resolves inside the network is caught too.
func TestDialWebhookAddr_PrivateNeedsTheAllowlist(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := dialWebhookAddr(ctx, "tcp", "10.10.10.1:8006", nil)
	if err == nil || !strings.Contains(err.Error(), "address refused") {
		t.Fatalf("private dial without allowlist = %v, want address refused", err)
	}
	_, lan, _ := net.ParseCIDR("10.10.10.0/24")
	_, err = dialWebhookAddr(ctx, "tcp", "10.10.10.1:8006", []*net.IPNet{lan})
	if err != nil && strings.Contains(err.Error(), "address refused") {
		t.Fatalf("allowlisted dial was refused: %v", err)
	}
}
