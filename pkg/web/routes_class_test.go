package web

import (
	"testing"

	"thesada.app/app/pkg/routetest"
)

// webRoutes classifies every route the package registers. A new route fails
// TestWebRoutesAreClassified until it is added here on purpose.
var webRoutes = map[string]routetest.Class{
	"GET /static/":                                    routetest.Public,
	"GET /sw.js":                                      routetest.Public,
	"GET /":                                           routetest.Public,
	"GET /login":                                      routetest.Public,
	"POST /login":                                     routetest.Public,
	"GET /login/totp":                                 routetest.Public,
	"POST /login/totp":                                routetest.Public,
	"POST /login/verify":                              routetest.Public,
	"GET /login/verify":                               routetest.Public,
	"GET /forgot-password":                            routetest.Public,
	"POST /forgot-password":                           routetest.Public,
	"GET /reset-password":                             routetest.Public,
	"POST /reset-password":                            routetest.Public,
	"POST /logout":                                    routetest.Public,
	"GET /signup":                                     routetest.Public,
	"POST /signup":                                    routetest.Public,
	"GET /devices":                                    routetest.User,
	"GET /devices/claim":                              routetest.User,
	"POST /devices/claim":                             routetest.User,
	"GET /devices/{id}":                               routetest.User,
	"GET /devices/{id}/chart.json":                    routetest.User,
	"POST /devices/{id}/sensors/delete":               routetest.User,
	"POST /devices/{id}/revoke":                       routetest.User,
	"GET /alerts":                                     routetest.User,
	"GET /settings":                                   routetest.User,
	"POST /settings/profile":                          routetest.User,
	"POST /settings/password":                         routetest.User,
	"POST /settings/totp/begin":                       routetest.User,
	"POST /settings/totp/confirm":                     routetest.User,
	"POST /settings/totp/disable":                     routetest.User,
	"POST /settings/notifications/add":                routetest.User,
	"POST /settings/notifications/delete":             routetest.User,
	"GET /auth/oidc/{slug}/start":                     routetest.Public,
	"GET /auth/oidc/{slug}/callback":                  routetest.Public,
	"POST /settings/oauth/{id}/unlink":                routetest.User,
	"GET /admin":                                      routetest.Admin,
	"GET /admin/tenants":                              routetest.Admin,
	"POST /admin/tenants":                             routetest.Admin,
	"POST /admin/tenants/{slug}/delete":               routetest.Admin,
	"GET /admin/tenants/{slug}/users":                 routetest.Admin,
	"POST /admin/tenants/{slug}/users":                routetest.Admin,
	"GET /admin/tenants/{slug}/users/{user_id}/edit":  routetest.Admin,
	"POST /admin/tenants/{slug}/users/{user_id}/edit": routetest.Admin,
	"POST /admin/tenants/{slug}/users/{user_id}/send-reset":   routetest.Admin,
	"POST /admin/tenants/{slug}/users/{user_id}/toggle-admin": routetest.Admin,
	"POST /admin/tenants/{slug}/users/{user_id}/delete":       routetest.Admin,
	"GET /admin/devices":                           routetest.Admin,
	"POST /admin/devices/bulk":                     routetest.Admin,
	"POST /admin/devices/{id}/reassign":            routetest.Admin,
	"POST /admin/devices/{id}/delete":              routetest.Admin,
	"GET /admin/devices/pair":                      routetest.Admin,
	"POST /admin/devices/{id}/pair/issue":          routetest.Admin,
	"POST /admin/devices/{id}/pair/revoke":         routetest.Admin,
	"GET /admin/ca.crt":                            routetest.Admin,
	"GET /admin/mqtt":                              routetest.Admin,
	"GET /admin/mqtt/ws":                           routetest.Admin,
	"GET /admin/waitlist":                          routetest.Admin,
	"POST /admin/waitlist/{id}/convert":            routetest.Admin,
	"POST /admin/waitlist/{id}/delete":             routetest.Admin,
	"GET /admin/devices/{id}/config":               routetest.Admin,
	"POST /admin/devices/{id}/config/cmd":          routetest.Admin,
	"GET /admin/devices/{id}/config/cmd/result":    routetest.Admin,
	"POST /admin/devices/{id}/config/write":        routetest.Admin,
	"POST /admin/devices/{id}/config/snapshot":     routetest.Admin,
	"GET /admin/devices/{id}/config/history":       routetest.Admin,
	"GET /admin/devices/{id}/rules":                routetest.Admin,
	"GET /admin/devices/{id}/rules/workspace":      routetest.Admin,
	"POST /admin/devices/{id}/rules/workspace":     routetest.Admin,
	"GET /admin/devices/{id}/rules/templates":      routetest.Admin,
	"POST /admin/devices/{id}/rules/templates":     routetest.Admin,
	"DELETE /admin/devices/{id}/rules/templates":   routetest.Admin,
	"GET /admin/devices/{id}/secrets":              routetest.Admin,
	"POST /admin/devices/{id}/secrets/set":         routetest.Admin,
	"POST /admin/devices/{id}/secrets/clear":       routetest.Admin,
	"POST /admin/devices/{id}/secrets/provision":   routetest.Admin,
	"GET /admin/tenants/{slug}/secrets":            routetest.Admin,
	"POST /admin/tenants/{slug}/secrets/set":       routetest.Admin,
	"POST /admin/tenants/{slug}/secrets/set-wifi":  routetest.Admin,
	"POST /admin/tenants/{slug}/secrets/clear":     routetest.Admin,
	"POST /admin/tenants/{slug}/secrets/provision": routetest.Admin,
	"POST /admin/impersonate/{slug}":               routetest.Admin,
	"POST /admin/impersonate":                      routetest.Admin,
	"GET /admin/debug":                             routetest.Admin,
	"GET /admin/audit":                             routetest.Admin,
	"GET /admin/observability":                     routetest.Admin,
}

// webCrossTenantRoutes are the user routes that name a tenant-owned object
// (path id, form id, or a tenant-scoped list). Each one needs a case in
// TestCrossTenant_WebRoutes (cross_tenant_integration_test.go).
var webCrossTenantRoutes = []string{
	"GET /devices",
	"GET /devices/{id}",
	"GET /devices/{id}/chart.json",
	"POST /devices/{id}/sensors/delete",
	"POST /devices/{id}/revoke",
	"GET /alerts",
	"POST /settings/notifications/delete",
	"POST /settings/oauth/{id}/unlink",
}

// TestWebRoutesAreClassified checks every route the package registers against
// webRoutes and webCrossTenantRoutes (rules in routetest.Check).
func TestWebRoutesAreClassified(t *testing.T) {
	routetest.Check(t, routetest.Registered(t, "."), webRoutes, webCrossTenantRoutes)
}
