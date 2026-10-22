package v1_test

import (
	"testing"

	"thesada.app/app/pkg/routetest"
)

// apiRoutes classifies every route the package registers. A new route fails
// TestAPIRoutesAreClassified until it is added here on purpose.
var apiRoutes = map[string]routetest.Class{
	"GET /healthz":                     routetest.Public,
	"GET /readyz":                      routetest.Public,
	"GET /version":                     routetest.Public,
	"POST /auth/login":                 routetest.Public,
	"POST /auth/logout":                routetest.Public,
	"POST /auth/magic-link":            routetest.Public,
	"POST /auth/magic-link/verify":     routetest.Public,
	"POST /auth/totp":                  routetest.Public,
	"POST /auth/signup":                routetest.Public,
	"GET /devices":                     routetest.User,
	"GET /devices/{id}":                routetest.User,
	"POST /devices/{id}/pair":          routetest.Admin,
	"POST /devices/claim":              routetest.User,
	"GET /devices/{id}/telemetry":      routetest.User,
	"GET /devices/{id}/alerts":         routetest.User,
	"GET /alerts":                      routetest.User,
	"GET /alert-subscriptions":         routetest.User,
	"POST /alert-subscriptions":        routetest.User,
	"DELETE /alert-subscriptions/{id}": routetest.User,
	"POST /devices/enroll":             routetest.Public,
	"POST /devices/enroll/verify":      routetest.Public,
	"POST /devices/enroll/cert":        routetest.Public,
	"POST /devices/enroll/ack":         routetest.Public,
	"POST /devices/enroll/status":      routetest.Public,
}

// apiCrossTenantRoutes are the user routes that name a tenant-owned object
// or list one. Each one needs a case in TestCrossTenant_APIRoutes.
var apiCrossTenantRoutes = []string{
	"GET /devices",
	"GET /devices/{id}",
	"GET /devices/{id}/telemetry",
	"GET /devices/{id}/alerts",
	"GET /alerts",
	"GET /alert-subscriptions",
	"DELETE /alert-subscriptions/{id}",
}

// TestAPIRoutesAreClassified checks every route the package registers against
// apiRoutes and apiCrossTenantRoutes (rules in routetest.Check).
func TestAPIRoutesAreClassified(t *testing.T) {
	routetest.Check(t, routetest.Registered(t, "."), apiRoutes, apiCrossTenantRoutes)
}
