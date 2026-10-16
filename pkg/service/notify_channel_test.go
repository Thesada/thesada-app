package service

import (
	"errors"
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

func TestValidWebhookURL_AllowsPrivateAndRefusesLoopback(t *testing.T) {
	if !ValidWebhookURL("https://hooks.example/alert") {
		t.Fatal("https rejected")
	}
	if ValidWebhookURL("javascript:alert(1)") || ValidWebhookURL("https://") {
		t.Fatal("bad url accepted")
	}
	if ValidWebhookURL("http://127.0.0.1/hook") || ValidWebhookURL("http://localhost/hook") || ValidWebhookURL("http://169.254.169.254/") {
		t.Fatal("loopback or link-local accepted")
	}
	if !ValidWebhookURL("http://10.1.1.5/hook") {
		t.Fatal("private address rejected")
	}
}

func TestWebhookDestinationError_OnlyChecksWebhook(t *testing.T) {
	if err := WebhookDestinationError("email", "not a url"); err != nil {
		t.Fatalf("email channel = %v", err)
	}
	if !errors.Is(WebhookDestinationError("webhook", "http://127.0.0.1/hook"), ErrBadWebhook) {
		t.Fatal("loopback webhook was accepted")
	}
	if err := WebhookDestinationError("webhook", "https://hooks.example/alert"); err != nil {
		t.Fatalf("https webhook = %v", err)
	}
}
