// redispatch.go - startup + periodic re-dispatch of pending alerts.
//
// The inline post-ingest Dispatch is fire-and-forget, so a failed send or a
// process death mid-alert would otherwise leave the row undelivered forever.
// The sweep scan must see every tenant's rows, so it runs on the Admin
// (BYPASSRLS) pool via db.WithAdminAudit - scan only, (tenant_id, alert id)
// pairs; each re-dispatch runs tenant-scoped on the App pool like the inline
// path.

package alerts

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

// sweepBatchLimit bounds one sweep pass. Dispatches run sequentially, so the
// cap keeps a huge backlog (e.g. SMTP outage recovery) from pinning a sweep
// for longer than a few ticks; the next tick picks up where this one stopped.
const sweepBatchLimit = 100

// StartRedispatcher launches the background sweep loop: one pass immediately
// (startup redispatch of anything a previous process left pending), then one
// per AlertRedispatchInterval until ctx is cancelled.
// in: ctx (cancel stops the loop). out: done channel, closed on exit (test coordination).
func (n *Notifier) StartRedispatcher(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		interval := n.cfg.AlertRedispatchInterval
		if interval <= 0 {
			interval = time.Minute
		}
		n.Sweep(ctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				n.Sweep(ctx)
			}
		}
	}()
	return done
}

// Sweep runs one redispatch pass: scan pending-and-due alerts across all
// tenants, then Dispatch each under its own tenant. Sequential on purpose -
// keeps SMTP/Telegram pressure bounded; one bad row never stops the pass.
// in: ctx. out: none (logs per-alert errors).
func (n *Notifier) Sweep(ctx context.Context) {
	type due struct {
		tenantID string
		alertID  int64
	}
	var batch []due
	err := db.WithAdminAudit(ctx, n.admin, "alert redispatch sweep", func(tx pgx.Tx) error {
		const query = `
			SELECT d.tenant_id, a.id
			FROM device_alerts a
			JOIN devices d ON d.id = a.device_pk
			WHERE a.delivery_status = 'pending'
			  AND a.next_attempt_at <= now()
			ORDER BY a.id
			LIMIT $1`
		rows, err := tx.Query(ctx, query, sweepBatchLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d due
			if err := rows.Scan(&d.tenantID, &d.alertID); err != nil {
				return err
			}
			batch = append(batch, d)
		}
		return rows.Err()
	})
	if err != nil {
		slog.Error("alert redispatch scan failed", "err", err)
		return
	}
	if len(batch) == 0 {
		return
	}
	slog.Info("alert.delivery.redispatch", "due", len(batch), "batch_limit", sweepBatchLimit)
	for _, d := range batch {
		if err := n.Dispatch(ctx, d.tenantID, d.alertID); err != nil {
			slog.Error("alert redispatch failed", "alert_id", d.alertID, "err", err)
		}
	}
}
