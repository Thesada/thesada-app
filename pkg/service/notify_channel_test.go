package service

import (
	"errors"
	"net"
	"testing"
)

func TestValidNotifyChannel_AcceptsEmailTelegramAndWebhook(t *testing.T) {
	for _, ok := range []string{"email", "telegram", "webhook"} {
		if !ValidNotifyChannel(ok) {
			t.Errorf("%s rejected", ok)
		}
	}
	if ValidNotifyChannel("sms") {
		t.Fatal("sms accepted")
	}
}

func TestValidWebhookURL_RefusesInternalUnlessAllowed(t *testing.T) {
	if !ValidWebhookURL("https://hooks.example/alert", nil) {
		t.Fatal("https rejected")
	}
	if ValidWebhookURL("javascript:alert(1)", nil) || ValidWebhookURL("https://", nil) {
		t.Fatal("bad url accepted")
	}
	for _, internal := range []string{
		"http://127.0.0.1/hook", "http://localhost/hook", "http://169.254.169.254/",
		"http://10.9.9.1:8080/", "http://192.168.1.5/hook", "http://172.16.0.9/",
		"http://100.64.0.1/hook", "http://[fd00::1]/hook",
	} {
		if ValidWebhookURL(internal, nil) {
			t.Errorf("%s accepted without an allowlist", internal)
		}
	}
	_, home, _ := net.ParseCIDR("10.0.0.0/24")
	allow := []*net.IPNet{home}
	if !ValidWebhookURL("http://10.0.0.30:8123/api/webhook/x", allow) {
		t.Fatal("allowlisted private address rejected")
	}
	if ValidWebhookURL("http://10.9.9.1:8080/", allow) {
		t.Fatal("private address outside the allowlist accepted")
	}
	_, all, _ := net.ParseCIDR("0.0.0.0/0")
	if ValidWebhookURL("http://127.0.0.1/hook", []*net.IPNet{all}) {
		t.Fatal("loopback accepted because an allowlist covers it")
	}
}

func TestWebhookDestinationError_OnlyChecksWebhook(t *testing.T) {
	if err := WebhookDestinationError("email", "not a url", nil); err != nil {
		t.Fatalf("email channel = %v", err)
	}
	if !errors.Is(WebhookDestinationError("webhook", "http://127.0.0.1/hook", nil), ErrBadWebhook) {
		t.Fatal("loopback webhook was accepted")
	}
	if err := WebhookDestinationError("webhook", "https://hooks.example/alert", nil); err != nil {
		t.Fatalf("https webhook = %v", err)
	}
}
