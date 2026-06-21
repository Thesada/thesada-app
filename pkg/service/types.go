// Package service provides the business-logic layer for thesada-app.
// This file defines the Go structs that map to SQL tables.
package service

import (
	"time"

	"github.com/google/uuid"
)

// Device maps to the devices table. Exported so handler helpers in other
// packages can declare the type explicitly (super-admin cross-tenant lookup).
type Device struct {
	ID              uuid.UUID  `json:"id"`
	TenantID        string     `json:"tenant_id"`
	OwnerUserID     *uuid.UUID `json:"owner_user_id"`
	DeviceID        string     `json:"device_id"`
	PairingKey      *string    `json:"pairing_key"`
	PairedAt        *time.Time `json:"paired_at"`
	DisplayName     *string    `json:"display_name"`
	HardwareType    *string    `json:"hardware_type"`
	FirmwareVersion *string    `json:"firmware_version"`
	LastSeenAt      *time.Time `json:"last_seen_at"`
	MQTTTopicPrefix *string    `json:"mqtt_topic_prefix"`
	CreatedAt       time.Time  `json:"created_at"`

	// Latest uptime sample from device_telemetry (metric='uptime'), populated
	// by list queries only. Nil for single-row fetches (GetByID, GetByDeviceID,
	// Upsert return paths). Render "live" uptime as
	// LastUptimeSeconds + (now - LastUptimeAt).
	LastUptimeSeconds *int64     `json:"last_uptime_seconds,omitempty"`
	LastUptimeAt      *time.Time `json:"last_uptime_at,omitempty"`
}

// TenantAlertRow is a denormalized alert joined with the device_id label,
// for the tenant-wide alert browse view. Exported so pkg/web can iterate.
type TenantAlertRow struct {
	ID         int64     `json:"id"`
	DevicePK   uuid.UUID `json:"device_pk"`
	DeviceID   string    `json:"device_id"`
	ReceivedAt time.Time `json:"received_at"`
	Severity   string    `json:"severity"`
	Code       *string   `json:"code"`
	Message    string    `json:"message"`
}

// device_telemetry maps to the device_telemetry table.
type device_telemetry struct {
	ID         int64     `json:"id"`
	DevicePK   uuid.UUID `json:"device_pk"`
	ReceivedAt time.Time `json:"received_at"`
	Metric     string    `json:"metric"`
	ValueNum   *float64  `json:"value_num"`
	ValueText  *string   `json:"value_text"`
	Raw        []byte    `json:"raw"`
}

// device_alerts maps to the device_alerts table.
type device_alerts struct {
	ID                int64     `json:"id"`
	DevicePK          uuid.UUID `json:"device_pk"`
	ReceivedAt        time.Time `json:"received_at"`
	Severity          string    `json:"severity"`
	Code              *string   `json:"code"`
	Message           string    `json:"message"`
	Raw               []byte    `json:"raw"`
	DeliveredEmail    bool      `json:"delivered_email"`
	DeliveredTelegram bool      `json:"delivered_telegram"`
}

// DeviceCertificate maps to the device_certificates table. Stores X.509
// client certs issued by the app's CA for per-device mTLS authentication.
type DeviceCertificate struct {
	ID        int64      `json:"id"`
	DevicePK  uuid.UUID  `json:"device_pk"`
	SerialHex string     `json:"serial_hex"`
	CN        string     `json:"cn"`
	NotBefore time.Time  `json:"not_before"`
	NotAfter  time.Time  `json:"not_after"`
	CertPEM   string     `json:"cert_pem"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at"`
	CreatedAt time.Time  `json:"created_at"`
}

// DeviceFile is the canonical current state of a file on a device.
// One row per (DevicePK, Path) in device_files. Upsert on each push
// or successful pull. Recovery + drift compare both hit this.
type DeviceFile struct {
	DevicePK  uuid.UUID  `json:"device_pk"`
	Path      string     `json:"path"`
	Content   string     `json:"content"`
	SHA256    string     `json:"sha256"`
	Source    string     `json:"source"`
	UpdatedAt time.Time  `json:"updated_at"`
	UpdatedBy *uuid.UUID `json:"updated_by"`
}

// DeviceFileHistory is an immutable change log entry. One row per sha
// change of a (DevicePK, Path). Drives version-history UI; pruned by
// retention. PrevSHA256 chains the entries for a path.
type DeviceFileHistory struct {
	ID         int64      `json:"id"`
	DevicePK   uuid.UUID  `json:"device_pk"`
	Path       string     `json:"path"`
	Content    string     `json:"content"`
	SHA256     string     `json:"sha256"`
	PrevSHA256 *string    `json:"prev_sha256"`
	Source     string     `json:"source"`
	CreatedBy  *uuid.UUID `json:"created_by"`
	CreatedAt  time.Time  `json:"created_at"`
}

// DeviceFileObservation is drift telemetry: what hash the device's
// retained <prefix>/info reported, when. No content payload - that
// lives in DeviceFile (current) or DeviceFileHistory (older).
type DeviceFileObservation struct {
	ID             int64     `json:"id"`
	DevicePK       uuid.UUID `json:"device_pk"`
	Path           string    `json:"path"`
	ReportedSHA256 string    `json:"reported_sha256"`
	ObservedAt     time.Time `json:"observed_at"`
}
