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
	"net/url"
	"time"

	"thesada.app/app/pkg/service"
)

const webhookTimeout = 10 * time.Second

// webhookDialer dials addr after refusing a resolved address we will not POST.
// in: operator allowlist. out: DialContext func.
func webhookDialer(allow []*net.IPNet) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialWebhookAddr(ctx, network, addr, allow)
	}
}

// dialWebhookAddr dials addr after refusing a resolved address we will not POST.
// in: ctx, network, host:port, operator allowlist. out: conn, error.
func dialWebhookAddr(ctx context.Context, network, addr string, allow []*net.IPNet) (net.Conn, error) {
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
		if service.WebhookIPRefused(ip.IP, allow) {
			return nil, fmt.Errorf("webhook dial %s: address refused", ip.IP)
		}
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	var lastErr error
	for _, ip := range ips {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("webhook dial %s: %w", host, lastErr)
}

// newWebhookClient refuses redirects and every address WebhookIPRefused refuses.
// in: operator allowlist. out: client.
func newWebhookClient(allow []*net.IPNet) *http.Client {
	transport := &http.Transport{DialContext: webhookDialer(allow)}
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
	if !service.ValidWebhookURL(dest, n.webhookAllow) {
		return errors.New("webhook url refused")
	}
	if n.webhookHTTP == nil {
		return fmt.Errorf("webhook client not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, dest, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("webhook request: %w", webhookErr(err))
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "thesada-app")
	resp, err := n.webhookHTTP.Do(req)
	if err != nil {
		return fmt.Errorf("webhook post: %w", webhookErr(err))
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1024))
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook status %d", resp.StatusCode)
	}
	return nil
}

// webhookErr drops the URL a client error would otherwise carry into the log.
// in: error from net/http. out: the same failure without the destination.
func webhookErr(err error) error {
	var uerr *url.Error
	if errors.As(err, &uerr) && uerr.Err != nil {
		return uerr.Err
	}
	return err
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
