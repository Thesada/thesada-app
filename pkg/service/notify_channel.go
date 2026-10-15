package service

import (
	"errors"
	"net"
	"net/url"
	"strings"
)

// ErrBadWebhook means a webhook subscription has no http(s) URL we will POST.
var ErrBadWebhook = errors.New("bad webhook url")

// ValidNotifyChannel reports whether channel is one the settings page can add.
// in: channel name. out: true for email, telegram, or webhook.
func ValidNotifyChannel(channel string) bool {
	switch channel {
	case "email", "telegram", "webhook":
		return true
	default:
		return false
	}
}

// ValidWebhookURL reports whether raw is an http(s) URL we will POST.
// Loopback and link-local hosts are refused. Private ranges stay allowed.
// in: raw URL. out: true when the destination is acceptable.
func ValidWebhookURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return false
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return false
	}
	host := strings.ToLower(u.Hostname())
	if host == "" || host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	if ip := net.ParseIP(host); ip != nil && WebhookIPRefused(ip) {
		return false
	}
	return true
}

// WebhookDestinationError rejects a webhook channel whose URL we will not POST.
// Other channels are not URL-checked.
// in: channel, destination. out: ErrBadWebhook or nil.
func WebhookDestinationError(channel, destination string) error {
	if channel != "webhook" {
		return nil
	}
	if !ValidWebhookURL(destination) {
		return ErrBadWebhook
	}
	return nil
}

// WebhookIPRefused reports loopback, link-local, multicast, and unspecified addresses.
// in: ip. out: true when a webhook must not dial it.
func WebhookIPRefused(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}
