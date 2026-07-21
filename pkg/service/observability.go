// ObservabilityService - DB-derived platform health snapshot for the
// /admin/observability page. Everything here is an aggregate over tables
// the app already maintains (waitlist, device_alerts, devices,
// device_certificates, admin_audit); there is no metrics infrastructure
// behind it. Cross-tenant BY DESIGN - the page is a super-admin platform
// view, so every query runs through WithAdminAudit on the BYPASSRLS pool.
package service

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// ObservabilityService reads aggregate platform-health stats.
type ObservabilityService struct {
	cfg   *config.Config
	pools db.Pools
}

// WaitlistFunnel is the signup conversion funnel: everyone who ever
// joined, split by whether an operator converted them to a user yet.
type WaitlistFunnel struct {
	Total     int
	Pending   int
	Converted int
}

// AlertDeliveryCount is one delivery_status bucket of device_alerts,
// counted over the trailing 24h / 7d windows (received_at based).
type AlertDeliveryCount struct {
	Status  string
	Last24h int
	Last7d  int
}

// FleetStats is the device + certificate population: how many devices
// exist, how many are paired, and the cert lifecycle breakdown (unrevoked
// rows by status, plus the revoked total).
type FleetStats struct {
	TotalDevices  int
	PairedDevices int
	CertActive    int
	CertPending   int
	CertFailed    int
	CertRevoked   int
}

// AuditActionCount is one action bucket of admin_audit rows over the
// trailing 24h.
type AuditActionCount struct {
	Action string
	Count  int
}

// ObservabilityStats is the one-shot snapshot the admin page renders.
type ObservabilityStats struct {
	Waitlist WaitlistFunnel
	Alerts   []AlertDeliveryCount
	Fleet    FleetStats
	Audit    []AuditActionCount
}

// alertDeliveryStatuses is the full lifecycle vocabulary from 0025, in
// display order. Snapshot always emits every bucket (zeros included) so
// the page shows "dead 0" instead of silently omitting the state that
// matters most.
var alertDeliveryStatuses = []string{"pending", "delivered", "none", "dead"}

// Snapshot gathers every stat block in one call. Each block is its own
// query; they share one WithAdminAudit tx so the page renders a consistent
// point-in-time view.
// in: ctx. out: populated stats, error.
func (s *ObservabilityService) Snapshot(ctx context.Context) (*ObservabilityStats, error) {
	var out ObservabilityStats
	err := db.WithAdminAudit(ctx, s.pools.Admin, "observability.snapshot", func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx,
			`SELECT count(*),
			        count(*) FILTER (WHERE converted_user_id IS NOT NULL)
			   FROM waitlist`).Scan(&out.Waitlist.Total, &out.Waitlist.Converted); err != nil {
			return fmt.Errorf("waitlist funnel: %w", err)
		}
		out.Waitlist.Pending = out.Waitlist.Total - out.Waitlist.Converted

		alerts, err := alertDeliveryCounts(ctx, tx)
		if err != nil {
			return err
		}
		out.Alerts = alerts

		if err := tx.QueryRow(ctx,
			`SELECT count(*),
			        count(*) FILTER (WHERE paired_at IS NOT NULL)
			   FROM devices`).Scan(&out.Fleet.TotalDevices, &out.Fleet.PairedDevices); err != nil {
			return fmt.Errorf("fleet devices: %w", err)
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FILTER (WHERE NOT revoked AND status = 'active'),
			        count(*) FILTER (WHERE NOT revoked AND status = 'pending'),
			        count(*) FILTER (WHERE NOT revoked AND status = 'failed'),
			        count(*) FILTER (WHERE revoked)
			   FROM device_certificates`).Scan(
			&out.Fleet.CertActive, &out.Fleet.CertPending,
			&out.Fleet.CertFailed, &out.Fleet.CertRevoked); err != nil {
			return fmt.Errorf("fleet certs: %w", err)
		}

		audit, err := auditActionCounts(ctx, tx)
		if err != nil {
			return err
		}
		out.Audit = audit
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("observability: snapshot: %w", err)
	}
	return &out, nil
}

// alertDeliveryCounts counts device_alerts per delivery_status over 24h/7d
// windows, then normalizes onto the full status vocabulary so zero buckets
// still render.
// in: ctx, open tx. out: one row per lifecycle status, error.
func alertDeliveryCounts(ctx context.Context, tx pgx.Tx) ([]AlertDeliveryCount, error) {
	rows, err := tx.Query(ctx,
		`SELECT delivery_status,
		        count(*) FILTER (WHERE received_at >= now() - interval '24 hours'),
		        count(*) FILTER (WHERE received_at >= now() - interval '7 days')
		   FROM device_alerts
		  GROUP BY delivery_status`)
	if err != nil {
		return nil, fmt.Errorf("alert delivery counts: %w", err)
	}
	defer rows.Close()
	byStatus := make(map[string]AlertDeliveryCount, len(alertDeliveryStatuses))
	for rows.Next() {
		var c AlertDeliveryCount
		if err := rows.Scan(&c.Status, &c.Last24h, &c.Last7d); err != nil {
			return nil, err
		}
		byStatus[c.Status] = c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]AlertDeliveryCount, 0, len(alertDeliveryStatuses))
	for _, status := range alertDeliveryStatuses {
		c := byStatus[status]
		c.Status = status
		out = append(out, c)
	}
	return out, nil
}

// auditActionCounts counts admin_audit rows per action over the trailing
// 24h, busiest first.
// in: ctx, open tx. out: action buckets, error.
func auditActionCounts(ctx context.Context, tx pgx.Tx) ([]AuditActionCount, error) {
	rows, err := tx.Query(ctx,
		`SELECT action, count(*)
		   FROM admin_audit
		  WHERE at >= now() - interval '24 hours'
		  GROUP BY action
		  ORDER BY count(*) DESC, action`)
	if err != nil {
		return nil, fmt.Errorf("audit action counts: %w", err)
	}
	defer rows.Close()
	var out []AuditActionCount
	for rows.Next() {
		var c AuditActionCount
		if err := rows.Scan(&c.Action, &c.Count); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
