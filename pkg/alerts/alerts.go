// Package alerts fans device alerts out to email and Telegram subscribers.
// A single Dispatch call resolves the alert row, walks matching subscriptions,
// and records per-channel delivery state on device_alerts.
package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
	"thesada.app/app/pkg/mailer"
)

// alertEmailHTML is the auto-escaped MIME/HTML body for alert notifications.
// Severity-coloured header bar uses the same palette as the dashboard alert
// list (red=crit, amber=warn, slate=info).
var alertEmailHTML = template.Must(template.New("alert").Parse(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>{{.Subject}}</title></head>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#0f172a;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f1f5f9;padding:24px 0;">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0" style="background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
        <tr>
          <td style="padding:16px 24px;{{if eq .Severity "crit"}}background:#fee2e2;color:#991b1b;{{else if eq .Severity "warn"}}background:#fef3c7;color:#92400e;{{else}}background:#f1f5f9;color:#475569;{{end}}">
            <strong style="text-transform:uppercase;font-size:12px;letter-spacing:0.08em;">{{.Severity}}</strong>
            {{if .Code}}<span style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;margin-left:8px;">[{{.Code}}]</span>{{end}}
          </td>
        </tr>
        <tr>
          <td style="padding:24px;">
            <h1 style="margin:0 0 8px 0;font-size:18px;font-weight:600;">{{.DeviceName}}</h1>
            <p style="margin:0 0 16px 0;font-size:13px;color:#64748b;">{{.ReceivedAt}}</p>
            <p style="margin:0;font-size:14px;line-height:1.5;">{{.Message}}</p>
          </td>
        </tr>
      </table>
      <p style="margin:16px 0 0 0;font-size:11px;color:#94a3b8;">thesada</p>
    </td></tr>
  </table>
</body>
</html>`))

// telegramAPITimeout caps each outbound request to api.telegram.org.
const telegramAPITimeout = 10 * time.Second

// Notifier owns the channels the platform can send alerts through.
// It is safe for concurrent use; instantiate once in main and share.
type Notifier struct {
	cfg    *config.Config
	db     *db.Pool
	mailer *mailer.Mailer
	http   *http.Client
}

// New constructs a Notifier bound to the given config, db pool, and mailer.
// in: cfg, db pool, mailer. out: ready *Notifier.
func New(cfg *config.Config, pool *db.Pool, mail *mailer.Mailer) *Notifier {
	return &Notifier{
		cfg:    cfg,
		db:     pool,
		mailer: mail,
		http:   &http.Client{Timeout: telegramAPITimeout},
	}
}

// alertRow is the joined snapshot each Dispatch call needs to render one notification.
type alertRow struct {
	severity      string
	code          *string
	message       string
	receivedAt    time.Time
	deviceID      string
	deviceDisplay *string
	alreadyEmail  bool
	alreadyTg     bool
}

// recipient is one subscription the alert was matched against.
type recipient struct {
	userID         string
	channel        string
	email          string
	telegramChatID *string
}

// Dispatch reads alert_subscriptions for the alert's device and sends
// notifications via every matching channel (email, telegram). Delivery state
// is recorded on device_alerts; a single row is only emailed once and only
// telegrammed once across retries.
// All queries run inside db.WithTenant on the App pool - the RLS policies on
// device_alerts / devices / alert_subscriptions / users key on app.tenant_id
// and return zero rows when the GUC is unset. The sends themselves happen
// outside the tx so slow SMTP/Telegram calls never hold a connection open.
// in: ctx, tenant id, device_alerts.id. out: error if the row lookup fails.
// Per-channel send errors are logged but do not fail the whole dispatch.
func (n *Notifier) Dispatch(ctx context.Context, tenantID string, alertID int64) error {
	var row *alertRow
	var recipients []recipient
	err := db.WithTenant(ctx, n.db, tenantID, func(tx pgx.Tx) error {
		var err error
		if row, err = n.loadAlert(ctx, tx, alertID); err != nil {
			return err
		}
		recipients, err = n.loadRecipients(ctx, tx, alertID)
		return err
	})
	if err != nil {
		return err
	}
	if len(recipients) == 0 {
		slog.Debug("alert has no subscribers", "alert_id", alertID)
		return nil
	}

	subject, body, htmlBody := renderAlert(row)
	var emailOK, tgOK bool
	for _, r := range recipients {
		switch r.channel {
		case "email":
			if row.alreadyEmail {
				continue
			}
			if err := n.mailer.SendMIME(r.email, subject, body, htmlBody); err != nil {
				slog.Error("alert email failed", "alert_id", alertID, "to", r.email, "err", err)
				continue
			}
			emailOK = true
		case "telegram":
			if row.alreadyTg {
				continue
			}
			if r.telegramChatID == nil || *r.telegramChatID == "" {
				slog.Warn("telegram subscription without chat_id", "alert_id", alertID, "user_id", r.userID)
				continue
			}
			if err := n.sendTelegram(ctx, *r.telegramChatID, body); err != nil {
				slog.Error("alert telegram failed", "alert_id", alertID, "chat_id", *r.telegramChatID, "err", err)
				continue
			}
			tgOK = true
		}
	}
	if emailOK || tgOK {
		err := db.WithTenant(ctx, n.db, tenantID, func(tx pgx.Tx) error {
			return n.markDelivered(ctx, tx, alertID, emailOK, tgOK)
		})
		if err != nil {
			slog.Error("alert delivery mark failed", "alert_id", alertID, "err", err)
		} else {
			slog.Info("alert.delivery.state_change",
				"from", "pending", "to", "delivered",
				"alert_id", alertID, "email", emailOK, "telegram", tgOK)
		}
	}
	return nil
}

// loadAlert fetches the joined alert + device row for rendering.
// in: ctx, tenant-scoped tx, alert id. out: populated *alertRow or error.
func (n *Notifier) loadAlert(ctx context.Context, tx pgx.Tx, alertID int64) (*alertRow, error) {
	const query = `
		SELECT a.severity, a.code, a.message, a.received_at,
		       d.device_id, d.display_name,
		       a.delivered_email, a.delivered_telegram
		FROM device_alerts a
		JOIN devices d ON d.id = a.device_pk
		WHERE a.id = $1`
	var r alertRow
	err := tx.QueryRow(ctx, query, alertID).Scan(
		&r.severity, &r.code, &r.message, &r.receivedAt,
		&r.deviceID, &r.deviceDisplay,
		&r.alreadyEmail, &r.alreadyTg)
	if err != nil {
		return nil, fmt.Errorf("alert lookup: %w", err)
	}
	return &r, nil
}

// loadRecipients walks alert_subscriptions for the alert's device or a
// tenant-wide wildcard row (device_pk IS NULL) and returns everyone whose
// min_severity threshold is met.
// in: ctx, tenant-scoped tx, alert id. out: [] recipient, error.
func (n *Notifier) loadRecipients(ctx context.Context, tx pgx.Tx, alertID int64) ([]recipient, error) {
	const query = `
		SELECT s.user_id::text, s.channel, u.email::text, u.telegram_chat_id
		FROM device_alerts a
		JOIN alert_subscriptions s
		  ON (s.device_pk = a.device_pk OR s.device_pk IS NULL)
		JOIN users u ON u.id = s.user_id
		WHERE a.id = $1
		  AND (CASE a.severity WHEN 'info' THEN 0 WHEN 'warn' THEN 1 WHEN 'crit' THEN 2 END)
		      >=
		      (CASE s.min_severity WHEN 'info' THEN 0 WHEN 'warn' THEN 1 WHEN 'crit' THEN 2 END)`
	rows, err := tx.Query(ctx, query, alertID)
	if err != nil {
		return nil, fmt.Errorf("recipients query: %w", err)
	}
	defer rows.Close()
	var out []recipient
	for rows.Next() {
		var r recipient
		if err := rows.Scan(&r.userID, &r.channel, &r.email, &r.telegramChatID); err != nil {
			return nil, fmt.Errorf("recipients scan: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("recipients rows: %w", err)
	}
	return out, nil
}

// markDelivered ORs the per-channel delivered flags so re-runs don't clear them.
// in: ctx, tenant-scoped tx, alert id, whether email fired this run, whether telegram fired. out: error.
func (n *Notifier) markDelivered(ctx context.Context, tx pgx.Tx, alertID int64, email, tg bool) error {
	const query = `
		UPDATE device_alerts
		SET delivered_email = delivered_email OR $2,
		    delivered_telegram = delivered_telegram OR $3
		WHERE id = $1`
	if _, err := tx.Exec(ctx, query, alertID, email, tg); err != nil {
		return fmt.Errorf("mark delivered: %w", err)
	}
	return nil
}

// renderAlert builds a human-readable subject + plain text body + MIME html
// body for one alert. HTML variant uses the severity-coloured card template.
// in: *alertRow. out: subject, text body, html body.
func renderAlert(r *alertRow) (string, string, string) {
	name := r.deviceID
	if r.deviceDisplay != nil && *r.deviceDisplay != "" {
		name = *r.deviceDisplay
	}
	code := ""
	if r.code != nil && *r.code != "" {
		code = " [" + *r.code + "]"
	}
	subject := fmt.Sprintf("[thesada %s]%s %s", r.severity, code, name)
	text := fmt.Sprintf("Device: %s\nSeverity: %s%s\nTime: %s\n\n%s\n",
		name, r.severity, code, r.receivedAt.Format(time.RFC3339), r.message)

	data := struct {
		Subject    string
		DeviceName string
		Severity   string
		Code       string
		Message    string
		ReceivedAt string
	}{
		Subject:    subject,
		DeviceName: name,
		Severity:   r.severity,
		Message:    r.message,
		ReceivedAt: r.receivedAt.Format(time.RFC3339),
	}
	if r.code != nil {
		data.Code = *r.code
	}
	var htmlBuf bytes.Buffer
	if err := alertEmailHTML.Execute(&htmlBuf, data); err != nil {
		// Fall back to text-only if the template blows up for any reason.
		slog.Error("alert html render failed", "err", err)
		return subject, text, ""
	}
	return subject, text, htmlBuf.String()
}

// sendTelegram POSTs a sendMessage request to the Telegram bot API.
// in: ctx, chat id, message body. out: error if config missing, network failure, or non-200 response.
func (n *Notifier) sendTelegram(ctx context.Context, chatID, body string) error {
	if n.cfg.TelegramBotToken == "" {
		return errors.New("telegram bot token not configured")
	}
	payload, err := json.Marshal(map[string]string{
		"chat_id": chatID,
		"text":    body,
	})
	if err != nil {
		return err
	}
	url := "https://api.telegram.org/bot" + n.cfg.TelegramBotToken + "/sendMessage"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("telegram api status %d", resp.StatusCode)
	}
	return nil
}
