package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"thesada.app/app/pkg/service"
)

const webhookTimeout = 10 * time.Second

// dialWebhookAddr dials addr after refusing a resolved address we will not POST.
// in: ctx, network, host:port. out: conn, error.
func dialWebhookAddr(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("webhook dial %s: %w", addr, err)
	}
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("webhook dial %s: %w", host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("webhook dial %s: address refused", host)
	}
	for _, ip := range ips {
		if service.WebhookIPRefused(ip.IP) {
			return nil, fmt.Errorf("webhook dial %s: address refused", ip.IP)
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
	if err != nil {
		return nil, fmt.Errorf("webhook dial %s: %w", host, err)
	}
	return conn, nil
}

// newWebhookClient refuses redirects and link-local or loopback addresses.
// in: none. out: client.
func newWebhookClient() *http.Client {
	transport := &http.Transport{DialContext: dialWebhookAddr}
	return &http.Client{
		Timeout:   webhookTimeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("webhook redirect refused")
		},
	}
}

// sendWebhook POSTs one alert as JSON. Redirects are refused.
// in: ctx, destination URL, JSON body. out: error.
func (n *Notifier) sendWebhook(ctx context.Context, dest string, payload []byte) error {
	if !service.ValidWebhookURL(dest) {
		return fmt.Errorf("webhook url refused: %s", dest)
	}
	if n.webhookHTTP == nil {
		return fmt.Errorf("webhook client not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "thesada-app")
	resp, err := n.webhookHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("webhook post: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// webhookPayload is the JSON body posted to a subscription URL.
// code is always present. An alert with no code sends an empty string.
// in: alert id, row. out: JSON, error.
func webhookPayload(alertID int64, r *alertRow) ([]byte, error) {
	code := ""
	if r.code != nil {
		code = *r.code
	}
	body := map[string]any{
		"alert_id":    alertID,
		"device_id":   r.deviceID,
		"severity":    r.severity,
		"code":        code,
		"message":     r.message,
		"received_at": r.receivedAt.UTC().Format(time.RFC3339),
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("webhook payload: %w", err)
	}
	return b, nil
}
