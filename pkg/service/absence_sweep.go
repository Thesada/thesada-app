package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/db"
)

const absenceBatchLimit = 100

type absenceCandidate struct {
	tenantID    string
	devicePk    uuid.UUID
	deviceID    string
	lastSeen    time.Time
	lastAbsence *time.Time
}

// RaiseAbsencesAny inserts one warn alert per paired device that has been quiet
// for AbsenceWindow and has no absence alert since it was last seen.
// in: ctx. out: none (logs per device).
func (s *AlertService) RaiseAbsencesAny(ctx context.Context) {
	var batch []absenceCandidate
	err := db.WithAdminAudit(ctx, s.pools.Admin, "alert absence sweep", func(tx pgx.Tx) error {
		const query = `
			SELECT d.tenant_id, d.id, d.device_id, d.last_seen_at,
			       MAX(a.received_at) FILTER (WHERE a.code = 'absence')
			FROM devices d
			LEFT JOIN device_alerts a ON a.device_pk = d.id
			WHERE d.paired_at IS NOT NULL
			  AND d.last_seen_at IS NOT NULL
			  AND d.last_seen_at <= now() - $1::interval
			  AND NOT EXISTS (
			    SELECT 1 FROM device_alerts prior
			    WHERE prior.device_pk = d.id AND prior.code = 'absence'
			      AND prior.received_at >= d.last_seen_at)
			GROUP BY d.tenant_id, d.id, d.device_id, d.last_seen_at
			ORDER BY d.last_seen_at
			LIMIT $2`
		rows, err := tx.Query(ctx, query, fmt.Sprintf("%d minutes", int(AbsenceWindow/time.Minute)), absenceBatchLimit)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r absenceCandidate
			if err := rows.Scan(&r.tenantID, &r.devicePk, &r.deviceID, &r.lastSeen, &r.lastAbsence); err != nil {
				return err
			}
			batch = append(batch, r)
		}
		return rows.Err()
	})
	if err != nil {
		slog.Error("alert absence scan failed", "err", err)
		return
	}
	now := time.Now()
	for _, r := range batch {
		var last time.Time
		if r.lastAbsence != nil {
			last = *r.lastAbsence
		}
		if !AbsenceEpisodeOpen(r.lastSeen, now, AbsenceWindow, last) {
			continue
		}
		raw, err := json.Marshal(map[string]string{
			"kind":      "absence",
			"last_seen": r.lastSeen.UTC().Format(time.RFC3339Nano),
		})
		if err != nil {
			slog.Error("alert absence encode failed", "device", r.deviceID, "err", err)
			continue
		}
		msg := "no contact since " + r.lastSeen.UTC().Format(time.RFC3339)
		id, err := s.InsertAlert(ctx, r.tenantID, r.devicePk, "warn", "absence", msg, raw)
		if errors.Is(err, ErrDuplicateAlert) {
			// Two sweeps can insert the same payload. Dedup means this episode is already raised.
			continue
		}
		if err != nil {
			slog.Error("alert absence insert failed", "device", r.deviceID, "err", err)
			continue
		}
		slog.Info("alert.absence.raised", "tenant", r.tenantID, "device", r.deviceID, "alert_id", id)
	}
}

// clearOpenAbsence marks absence alerts finished because the device was just seen.
// in: ctx, tenant tx, device pk. out: error.
func clearOpenAbsence(ctx context.Context, tx pgx.Tx, devicePk uuid.UUID) error {
	_, err := tx.Exec(ctx,
		`UPDATE device_alerts SET cleared_at = now()
		 WHERE device_pk = $1 AND code = 'absence' AND cleared_at IS NULL`,
		devicePk)
	if err != nil {
		return fmt.Errorf("clear absence: %w", err)
	}
	return nil
}

// StartAbsenceSweep raises absence alerts immediately and then on the same
// interval as alert redispatch. Delivery stays with the redispatch sweeper.
// in: ctx. out: done channel, closed when the loop exits.
func (s *AlertService) StartAbsenceSweep(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		interval := s.cfg.AlertRedispatchInterval
		if interval <= 0 {
			// A zero interval would spin the ticker. One minute is the floor.
			interval = time.Minute
		}
		s.RaiseAbsencesAny(ctx)
		s.RaiseCertExpiriesAny(ctx)
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				s.RaiseAbsencesAny(ctx)
				s.RaiseCertExpiriesAny(ctx)
			}
		}
	}()
	return done
}
