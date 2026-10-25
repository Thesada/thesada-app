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

// ValidWebhookURL reports whether raw is an http(s) URL we will POST. A
// literal IP goes through WebhookIPRefused; host names are checked again on
// every dial, against what they resolve to.
// in: raw URL, operator allowlist. out: true when the destination is acceptable.
func ValidWebhookURL(raw string, allow []*net.IPNet) bool {
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
	if ip := net.ParseIP(host); ip != nil && WebhookIPRefused(ip, allow) {
		return false
	}
	return true
}

// WebhookDestinationError rejects a webhook channel whose URL we will not POST.
// Other channels are not URL-checked.
// in: channel, destination, operator allowlist. out: ErrBadWebhook or nil.
func WebhookDestinationError(channel, destination string, allow []*net.IPNet) error {
	if channel != "webhook" {
		return nil
	}
	if !ValidWebhookURL(destination, allow) {
		return ErrBadWebhook
	}
	return nil
}

// cgnat is 100.64.0.0/10 (RFC 6598), the NetBird overlay range.
var cgnat = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// WebhookIPRefused reports addresses a webhook must not dial. Loopback,
// link-local, multicast and unspecified are always refused. Private (RFC 1918,
// fc00::/7) and CGNAT addresses are refused unless an operator listed them in
// THESADA_WEBHOOK_ALLOW_CIDRS: from the server, a tenant's webhook would
// otherwise reach the internal network.
// in: ip, operator allowlist. out: true when a webhook must not dial it.
func WebhookIPRefused(ip net.IP, allow []*net.IPNet) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}
	if !ip.IsPrivate() && !cgnat.Contains(ip) {
		return false
	}
	for _, n := range allow {
		if n.Contains(ip) {
			return false
		}
	}
	return true
}
