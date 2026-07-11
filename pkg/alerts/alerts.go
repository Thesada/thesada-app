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
	"sync"
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
	db     *db.Pool // App pool: every tenant-scoped query runs through db.WithTenant on it
	admin  *db.Pool // Admin pool (BYPASSRLS): redispatch sweep scan only, via db.WithAdminAudit
	mailer *mailer.Mailer
	http   *http.Client

	// Send seams: tests swap these to drive retry outcomes without a live
	// SMTP server or api.telegram.org.
	sendEmail func(to, subject, text, html string) error
	sendTG    func(ctx context.Context, chatID, body string) error

	// inflight keeps the inline post-ingest dispatch and the redispatch
	// sweeper from racing the same alert into a double-send. Per-process,
	// which matches the single-instance deployment; multiple instances would
	// need SELECT ... FOR UPDATE SKIP LOCKED claims instead.
	mu       sync.Mutex
	inflight map[int64]struct{}
}

// New constructs a Notifier bound to the given config, db pools, and mailer.
// Sends go through the App pool under the tenant GUC; the Admin pool is used
// only by the redispatch sweeper to scan for due alerts across tenants.
// in: cfg, db pools, mailer. out: ready *Notifier.
func New(cfg *config.Config, pools db.Pools, mail *mailer.Mailer) *Notifier {
	n := &Notifier{
		cfg:      cfg,
		db:       pools.App,
		admin:    pools.Admin,
		mailer:   mail,
		http:     &http.Client{Timeout: telegramAPITimeout},
		inflight: make(map[int64]struct{}),
	}
	n.sendEmail = func(to, subject, text, html string) error {
		// mailer.SendMIME silently no-ops when SMTP is unconfigured (documented
		// dev behaviour for magic links). For alerts that would mark the row
		// delivered with nothing sent, so fail here like the telegram channel
		// does on a missing token - the alert then retries and dead-letters loudly.
		if n.cfg.SMTPHost == "" {
			return errors.New("smtp host not configured")
		}
		return n.mailer.SendMIME(to, subject, text, html)
	}
	n.sendTG = n.sendTelegram
	return n
}

// claim marks an alert as being dispatched by this process; false means
// another goroutine already owns it and the caller must back off.
// in: alert id. out: whether the caller now owns the dispatch.
func (n *Notifier) claim(alertID int64) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, busy := n.inflight[alertID]; busy {
		return false
	}
	n.inflight[alertID] = struct{}{}
	return true
}

// release returns an alert claimed by claim.
// in: alert id. out: none.
func (n *Notifier) release(alertID int64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	delete(n.inflight, alertID)
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
	status        string
	attempts      int
}

// recipient is one subscription the alert was matched against.
type recipient struct {
	userID         string
	channel        string
	email          string
	telegramChatID *string
}

// Dispatch sends one alert through every matching subscription channel and
// records its delivery lifecycle (pending/delivered/none/dead + per-channel
// flags, so a retry never re-sends a channel that already succeeded). Queries
// run tenant-scoped via db.WithTenant on the App pool; the sends themselves
// happen outside the tx so slow SMTP/Telegram never holds a connection open.
// in: ctx, tenant id, device_alerts.id. out: error on row lookup failure;
// send errors drive the retry state instead of failing the call.
func (n *Notifier) Dispatch(ctx context.Context, tenantID string, alertID int64) error {
	if !n.claim(alertID) {
		slog.Debug("alert dispatch already in flight", "alert_id", alertID)
		return nil
	}
	defer n.release(alertID)

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
	if row.status != "pending" {
		// Idempotence gate: a sweeper pass that raced a finished dispatch, or
		// an operator re-poke of a delivered/dead row, must not re-send.
		slog.Debug("alert not pending, skipping dispatch", "alert_id", alertID, "status", row.status)
		return nil
	}
	if len(recipients) == 0 {
		slog.Debug("alert has no subscribers", "alert_id", alertID)
		return n.recordOutcome(ctx, tenantID, alertID, false, false, "none", row.attempts, time.Time{})
	}

	// A channel is "needed" when it has at least one matching subscription and
	// has not already been delivered by an earlier attempt.
	var needEmail, needTg bool
	for _, r := range recipients {
		switch r.channel {
		case "email":
			needEmail = needEmail || !row.alreadyEmail
		case "telegram":
			needTg = needTg || !row.alreadyTg
		}
	}

	subject, body, htmlBody := renderAlert(row)
	var emailOK, tgOK bool
	for _, r := range recipients {
		switch r.channel {
		case "email":
			if row.alreadyEmail {
				continue
			}
			if err := n.sendEmail(r.email, subject, body, htmlBody); err != nil {
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
			if err := n.sendTG(ctx, *r.telegramChatID, body); err != nil {
				slog.Error("alert telegram failed", "alert_id", alertID, "chat_id", *r.telegramChatID, "err", err)
				continue
			}
			tgOK = true
		}
	}

	attempts := row.attempts + 1
	emailDone := !needEmail || emailOK
	tgDone := !needTg || tgOK
	switch {
	case emailDone && tgDone:
		if err := n.recordOutcome(ctx, tenantID, alertID, emailOK, tgOK, "delivered", attempts, time.Time{}); err != nil {
			return nil
		}
		slog.Info("alert.delivery.state_change",
			"from", "pending", "to", "delivered",
			"alert_id", alertID, "email", emailOK || row.alreadyEmail, "telegram", tgOK || row.alreadyTg,
			"attempts", attempts)
	case attempts >= n.maxAttempts():
		if err := n.recordOutcome(ctx, tenantID, alertID, emailOK, tgOK, "dead", attempts, time.Time{}); err != nil {
			return nil
		}
		slog.Error("alert.delivery.state_change",
			"from", "pending", "to", "dead",
			"alert_id", alertID, "email", emailOK || row.alreadyEmail, "telegram", tgOK || row.alreadyTg,
			"attempts", attempts)
	default:
		next := time.Now().Add(retryBackoff(n.retryBase(), attempts))
		if err := n.recordOutcome(ctx, tenantID, alertID, emailOK, tgOK, "pending", attempts, next); err != nil {
			return nil
		}
		slog.Warn("alert.delivery.retry_scheduled",
			"alert_id", alertID, "attempt", attempts, "max", n.maxAttempts(),
			"next_attempt_at", next.Format(time.RFC3339))
	}
	return nil
}

// maxAttempts returns the configured dispatch budget with a sane floor.
// in: receiver. out: attempt budget >= 1.
func (n *Notifier) maxAttempts() int {
	if n.cfg.AlertMaxAttempts < 1 {
		return 1
	}
	return n.cfg.AlertMaxAttempts
}

// retryBase returns the configured first retry delay with a sane floor.
// in: receiver. out: base delay > 0.
func (n *Notifier) retryBase() time.Duration {
	if n.cfg.AlertRetryBase <= 0 {
		return time.Minute
	}
	return n.cfg.AlertRetryBase
}

// retryBackoff is the delay before attempt+1: base doubled per completed
// attempt, capped at 6 doublings so a misconfigured budget cannot push the
// next attempt out by days.
// in: base delay, completed attempts (>=1). out: delay until the next attempt.
func retryBackoff(base time.Duration, attempts int) time.Duration {
	shift := attempts - 1
	if shift > 6 {
		shift = 6
	}
	if shift < 0 {
		shift = 0
	}
	return base << shift
}

// recordOutcome persists one dispatch run: ORs the per-channel delivered
// flags (re-runs never clear them), sets status + attempts, and schedules the
// next sweep pick-up (zero time = keep current; terminal states are never swept).
// On write failure the row stays pending and the sweeper redispatches later -
// that can double-send a succeeded channel, acceptable over losing the alert.
// in: ctx, tenant id, alert id, per-channel success, status, attempts, next
// attempt time. out: error from the write (already logged).
func (n *Notifier) recordOutcome(ctx context.Context, tenantID string, alertID int64, email, tg bool, status string, attempts int, next time.Time) error {
	const query = `
		UPDATE device_alerts
		SET delivered_email = delivered_email OR $2,
		    delivered_telegram = delivered_telegram OR $3,
		    delivery_status = $4,
		    delivery_attempts = $5,
		    next_attempt_at = CASE WHEN $6::timestamptz IS NULL THEN next_attempt_at ELSE $6 END
		WHERE id = $1`
	var nextArg interface{}
	if !next.IsZero() {
		nextArg = next
	}
	err := db.WithTenant(ctx, n.db, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, query, alertID, email, tg, status, attempts, nextArg); err != nil {
			return fmt.Errorf("record delivery outcome: %w", err)
		}
		return nil
	})
	if err != nil {
		slog.Error("alert delivery mark failed", "alert_id", alertID, "status", status, "err", err)
	}
	return err
}

// loadAlert fetches the joined alert + device row for rendering.
// in: ctx, tenant-scoped tx, alert id. out: populated *alertRow or error.
func (n *Notifier) loadAlert(ctx context.Context, tx pgx.Tx, alertID int64) (*alertRow, error) {
	const query = `
		SELECT a.severity, a.code, a.message, a.received_at,
		       d.device_id, d.display_name,
		       a.delivered_email, a.delivered_telegram,
		       a.delivery_status, a.delivery_attempts
		FROM device_alerts a
		JOIN devices d ON d.id = a.device_pk
		WHERE a.id = $1`
	var r alertRow
	err := tx.QueryRow(ctx, query, alertID).Scan(
		&r.severity, &r.code, &r.message, &r.receivedAt,
		&r.deviceID, &r.deviceDisplay,
		&r.alreadyEmail, &r.alreadyTg,
		&r.status, &r.attempts)
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
