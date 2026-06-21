// Package service is the business-logic layer. It is the only layer that
// touches the database directly. Both pkg/web (HTMX) and pkg/api/v1 (JSON)
// call into it, so behavior stays consistent across frontends.
package service

import (
	"encoding/json"

	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/db"
)

// Services bundles every service the HTTP layers need.
// Construct once in main and pass to both pkg/web and pkg/api/v1.
type Services struct {
	Devices      *DeviceService
	Telemetry    *TelemetryService
	Alerts       *AlertService
	Auth         *AuthService
	Tenants      *TenantService
	Settings     *SettingsService
	DeviceFiles  *DeviceFilesService
	Certificates *CertificateService
	OAuth        *OAuthService
	ApiTokens    *ApiTokenService
}

// New constructs all services bound to the shared cfg + role-scoped pools.
// Sub-services pick the right pool field per call site (App for tenant
// reads, Admin for BYPASSRLS, MQTT for ingest); see db.Pools docs.
// in: cfg, db.Pools bundle. out: ready *Services bundle.
func New(cfg *config.Config, pools db.Pools) *Services {
	return &Services{
		Devices:      &DeviceService{cfg: cfg, pools: pools},
		Telemetry:    &TelemetryService{cfg: cfg, pools: pools},
		Alerts:       &AlertService{cfg: cfg, pools: pools},
		Auth:         &AuthService{cfg: cfg, pools: pools},
		Tenants:      &TenantService{cfg: cfg, pools: pools},
		Settings:     &SettingsService{cfg: cfg, pools: pools, cache: make(map[string]json.RawMessage)},
		DeviceFiles:  &DeviceFilesService{cfg: cfg, pools: pools},
		Certificates: &CertificateService{cfg: cfg, pools: pools},
		OAuth:        NewOAuthService(cfg, pools),
		ApiTokens:    &ApiTokenService{cfg: cfg, pools: pools},
	}
}
