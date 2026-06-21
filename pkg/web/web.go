// Package web serves the HTMX-driven dashboard. Pages are Go html/template
// rendered server-side and call pkg/service directly (not /api/v1 over HTTP).
// Tailwind CSS is delivered as a static asset built by the standalone CLI.
package web

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	texttemplate "text/template"
	"time"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/csrf"
	"thesada.app/app/pkg/mailer"
	"thesada.app/app/pkg/mqtt"
	"thesada.app/app/pkg/pki"
	"thesada.app/app/pkg/ratelimit"
	"thesada.app/app/pkg/service"
)

// bootstrapTenantID is the tenant used for pre-auth flows (login, signup,
// forgot-password) before a session exists. Today it is always "default";
// when multi-tenant mode lands it will be resolved from request host or path.
const bootstrapTenantID = "default"

// magicLinkMaxPerHour caps how many login or reset emails can be created for
// a given email (and, separately, a given source IP) inside a rolling hour.
const magicLinkMaxPerHour = 5

// magicLinkWindow is the rolling window for the rate limiter above.
const magicLinkWindow = time.Hour

//go:embed templates
var templatesFS embed.FS

//go:embed all:static
var staticFS embed.FS

// Server holds the HTMX page handlers, parsed templates, and the static asset filesystem.
type Server struct {
	cfg            *config.Config
	services       *service.Services
	mailer         *mailer.Mailer
	mqtt           *mqtt.Client
	ca             *pki.CA
	mux            *http.ServeMux
	handler        http.Handler
	templates      map[string]*template.Template
	emailHTML      map[string]*template.Template     // html variant, auto-escaped
	emailText      map[string]*texttemplate.Template // text variant, no escaping
	emailLimits    *ratelimit.Limiter
	ipLimits       *ratelimit.Limiter
	waitlistNotify *ratelimit.Limiter
	cliRequests    *cliRequestStore
}

// New constructs the HTMX server with all page routes wired up.
// The auth-resolver middleware wraps every request so CurrentUser works
// inside any handler; individual routes opt into authmw.RequireAuth.
// in: cfg, services bundle, mailer. out: ready *Server.
func New(cfg *config.Config, services *service.Services, mail *mailer.Mailer, mqttClient *mqtt.Client, ca *pki.CA) *Server {
	s := &Server{
		cfg:            cfg,
		services:       services,
		mailer:         mail,
		mqtt:           mqttClient,
		ca:             ca,
		mux:            http.NewServeMux(),
		emailLimits:    ratelimit.New(magicLinkWindow, magicLinkMaxPerHour),
		ipLimits:       ratelimit.New(magicLinkWindow, magicLinkMaxPerHour),
		waitlistNotify: ratelimit.New(24*time.Hour, 1),
		cliRequests:    newCLIRequestStore(cfg.CLIRequestTimeout + 60*time.Second),
	}
	s.parseTemplates()
	s.routes()
	s.handler = csrf.Middleware()(authmw.Middleware(services.Auth)(s.mux))

	// Periodic sweep so the rate-limiter maps do not accreted empty entries
	// over the lifetime of the systemd unit. Each fresh IP / email leaves a
	// residual key after Allow() trims its window; without a sweep the maps
	// grow unbounded (slow KB/year leak). Tied to context.Background since
	// the sweepers should live exactly as long as the process - they exit
	// when main returns..
	s.emailLimits.StartSweeper(context.Background())
	s.ipLimits.StartSweeper(context.Background())
	s.waitlistNotify.StartSweeper(context.Background())

	return s
}

// ServeHTTP dispatches to the auth-wrapped internal mux.
// in: writer, request. out: response from matched handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

// parseTemplates loads each page template paired with the shared layout.
// in: receiver. out: none (mutates s.templates).
func (s *Server) parseTemplates() {
	pages := []string{
		"login.html", "devices.html", "device-detail.html", "alerts.html",
		"signup.html", "settings.html", "forgot.html", "reset.html",
		"admin-index.html", "admin-tenants.html",
		"admin-tenant-users.html", "admin-tenant-user-edit.html",
		"admin-devices.html",
		"admin-mqtt.html", "admin-waitlist.html",
		"admin-device-config.html",
		"admin-devices-pair.html",
		"admin-debug.html",
	}
	s.templates = make(map[string]*template.Template, len(pages))
	for _, page := range pages {
		t := template.New("layout.html").Funcs(funcMap)
		t = template.Must(t.ParseFS(templatesFS, "templates/layout.html", "templates/"+page))
		s.templates[page] = t
	}
	// Email templates: each logical email has a .txt (text/template - no
	// escaping, plain bodies) and .html (html/template - auto-escape) pair.
	emailNames := []string{"login_link", "reset_link"}
	s.emailText = make(map[string]*texttemplate.Template, len(emailNames))
	s.emailHTML = make(map[string]*template.Template, len(emailNames))
	for _, name := range emailNames {
		tt := texttemplate.Must(texttemplate.ParseFS(templatesFS, "templates/emails/"+name+".txt"))
		s.emailText[name] = tt
		ht := template.Must(template.ParseFS(templatesFS, "templates/emails/"+name+".html"))
		s.emailHTML[name] = ht
	}
}

// renderEmail executes the text and html variants of an email template with
// the same data and returns both bodies. Returns an error if either variant
// is not loaded or fails to execute.
// in: template name (no extension), data. out: text body, html body, error.
func (s *Server) renderEmail(name string, data interface{}) (string, string, error) {
	tt, ok := s.emailText[name]
	if !ok {
		return "", "", errors.New("email text template not found: " + name)
	}
	ht, ok := s.emailHTML[name]
	if !ok {
		return "", "", errors.New("email html template not found: " + name)
	}
	var textBuf, htmlBuf bytes.Buffer
	if err := tt.Execute(&textBuf, data); err != nil {
		return "", "", err
	}
	if err := ht.Execute(&htmlBuf, data); err != nil {
		return "", "", err
	}
	return textBuf.String(), htmlBuf.String(), nil
}

// routes registers every page URL the HTMX dashboard handles.
// Protected routes are wrapped in authmw.RequireAuth; everything else is open.
// in: receiver. out: none (mutates s.mux).
func (s *Server) routes() {
	s.mux.Handle("GET /static/", http.FileServer(http.FS(staticFS)))
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /login", s.handleLoginForm)
	s.mux.HandleFunc("POST /login", s.handleLoginSubmit)
	s.mux.HandleFunc("GET /login/verify", s.handleMagicLinkVerify)
	s.mux.HandleFunc("GET /forgot-password", s.handleForgotForm)
	s.mux.HandleFunc("POST /forgot-password", s.handleForgotSubmit)
	s.mux.HandleFunc("GET /reset-password", s.handleResetForm)
	s.mux.HandleFunc("POST /reset-password", s.handleResetSubmit)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	s.mux.HandleFunc("GET /signup", s.handleSignupForm)
	s.mux.HandleFunc("POST /signup", s.handleSignupSubmit)
	s.mux.HandleFunc("GET /devices", authmw.RequireAuth(s.handleDeviceList))
	s.mux.HandleFunc("GET /devices/{id}", authmw.RequireAuth(s.handleDeviceDetail))
	s.mux.HandleFunc("GET /devices/{id}/chart.json", authmw.RequireAuth(s.handleDeviceChartJSON))
	s.mux.HandleFunc("POST /devices/{id}/sensors/delete", authmw.RequireAuth(s.handleDeviceSensorDelete))
	s.mux.HandleFunc("GET /alerts", authmw.RequireAuth(s.handleAlertList))
	s.mux.HandleFunc("GET /settings", authmw.RequireAuth(s.handleSettingsForm))
	s.mux.HandleFunc("POST /settings/profile", authmw.RequireAuth(s.handleSettingsProfile))
	s.mux.HandleFunc("POST /settings/password", authmw.RequireAuth(s.handleSettingsPassword))
	s.mux.HandleFunc("POST /settings/notifications/add", authmw.RequireAuth(s.handleSettingsNotificationAdd))
	s.mux.HandleFunc("POST /settings/notifications/delete", authmw.RequireAuth(s.handleSettingsNotificationDelete))
	s.mux.HandleFunc("GET /auth/oidc/{slug}/start", s.handleOIDCStart)
	s.mux.HandleFunc("GET /auth/oidc/{slug}/callback", s.handleOIDCCallback)
	s.mux.HandleFunc("POST /settings/oauth/{id}/unlink", authmw.RequireAuth(s.handleIdentityUnlink))

	// Super-admin only. RequireSuperAdmin returns 404 for non-super users so
	// the route tree is not discoverable from the outside.
	s.mux.HandleFunc("GET /admin", authmw.RequireSuperAdmin(s.handleAdminIndex))
	s.mux.HandleFunc("GET /admin/tenants", authmw.RequireSuperAdmin(s.handleAdminTenants))
	s.mux.HandleFunc("POST /admin/tenants", authmw.RequireSuperAdmin(s.handleAdminTenantCreate))
	s.mux.HandleFunc("POST /admin/tenants/{slug}/delete", authmw.RequireSuperAdmin(s.handleAdminTenantDelete))
	s.mux.HandleFunc("GET /admin/tenants/{slug}/users", authmw.RequireSuperAdmin(s.handleAdminTenantUsers))
	s.mux.HandleFunc("POST /admin/tenants/{slug}/users", authmw.RequireSuperAdmin(s.handleAdminTenantUserCreate))
	s.mux.HandleFunc("GET /admin/tenants/{slug}/users/{user_id}/edit", authmw.RequireSuperAdmin(s.handleAdminTenantUserEdit))
	s.mux.HandleFunc("POST /admin/tenants/{slug}/users/{user_id}/edit", authmw.RequireSuperAdmin(s.handleAdminTenantUserUpdate))
	s.mux.HandleFunc("POST /admin/tenants/{slug}/users/{user_id}/send-reset", authmw.RequireSuperAdmin(s.handleAdminTenantUserSendReset))
	s.mux.HandleFunc("POST /admin/tenants/{slug}/users/{user_id}/toggle-admin", authmw.RequireSuperAdmin(s.handleAdminTenantUserToggle))
	s.mux.HandleFunc("POST /admin/tenants/{slug}/users/{user_id}/delete", authmw.RequireSuperAdmin(s.handleAdminTenantUserDelete))
	s.mux.HandleFunc("GET /admin/devices", authmw.RequireSuperAdmin(s.handleAdminDevices))
	s.mux.HandleFunc("POST /admin/devices/bulk", authmw.RequireSuperAdmin(s.handleAdminDevicesBulk))
	s.mux.HandleFunc("POST /admin/devices/{id}/reassign", authmw.RequireSuperAdmin(s.handleAdminDeviceReassign))
	s.mux.HandleFunc("POST /admin/devices/{id}/delete", authmw.RequireSuperAdmin(s.handleAdminDeviceDelete))
	s.mux.HandleFunc("GET /admin/devices/pair", authmw.RequireSuperAdmin(s.handleAdminDevicePairIndex))
	s.mux.HandleFunc("POST /admin/devices/{id}/pair/issue", authmw.RequireSuperAdmin(s.handleAdminDevicePairIssue))
	s.mux.HandleFunc("POST /admin/devices/{id}/pair/revoke", authmw.RequireSuperAdmin(s.handleAdminDevicePairRevoke))
	s.mux.HandleFunc("GET /admin/ca.crt", authmw.RequireSuperAdmin(s.handleAdminCACert))
	s.mux.HandleFunc("GET /admin/mqtt", authmw.RequireSuperAdmin(s.handleAdminMqttShell))
	s.mux.HandleFunc("GET /admin/mqtt/ws", authmw.RequireSuperAdmin(s.handleAdminMqttWS))
	s.mux.HandleFunc("GET /admin/waitlist", authmw.RequireSuperAdmin(s.handleAdminWaitlist))
	s.mux.HandleFunc("POST /admin/waitlist/{id}/convert", authmw.RequireSuperAdmin(s.handleAdminWaitlistConvert))
	s.mux.HandleFunc("POST /admin/waitlist/{id}/delete", authmw.RequireSuperAdmin(s.handleAdminWaitlistDelete))
	s.mux.HandleFunc("GET /admin/devices/{id}/config", authmw.RequireSuperAdmin(s.handleAdminDeviceConfig))
	s.mux.HandleFunc("POST /admin/devices/{id}/config/cmd", authmw.RequireSuperAdmin(s.handleAdminDeviceConfigCmd))
	s.mux.HandleFunc("GET /admin/devices/{id}/config/cmd/result", authmw.RequireSuperAdmin(s.handleAdminDeviceConfigCmdResult))
	s.mux.HandleFunc("POST /admin/devices/{id}/config/write", authmw.RequireSuperAdmin(s.handleAdminDeviceConfigWrite))
	s.mux.HandleFunc("POST /admin/devices/{id}/config/snapshot", authmw.RequireSuperAdmin(s.handleAdminDeviceConfigSnapshot))
	s.mux.HandleFunc("GET /admin/devices/{id}/config/history", authmw.RequireSuperAdmin(s.handleAdminDeviceConfigHistory))
	s.mux.HandleFunc("POST /admin/impersonate/{slug}", authmw.RequireSuperAdmin(s.handleAdminImpersonate))
	s.mux.HandleFunc("POST /admin/impersonate", authmw.RequireSuperAdmin(s.handleAdminImpersonateClear))
	s.mux.HandleFunc("GET /admin/debug", authmw.RequireSuperAdmin(s.handleAdminDebug))
}

// render executes a parsed page template by name and writes the result.
// It also injects the current user (if any) into the template data so layouts
// can render a logout link when authenticated.
// in: writer, request, page filename, template data. out: HTML response.
func (s *Server) render(w http.ResponseWriter, r *http.Request, page string, data map[string]interface{}) {
	t, ok := s.templates[page]
	if !ok {
		http.Error(w, "template not found: "+page, http.StatusInternalServerError)
		return
	}
	if data == nil {
		data = map[string]interface{}{}
	}
	if _, set := data["Now"]; !set {
		data["Now"] = time.Now().Format("2006-01-02 15:04 MST")
	}
	if _, set := data["User"]; !set {
		data["User"] = authmw.CurrentUser(r)
	}
	if _, set := data["EffectiveTenantID"]; !set {
		data["EffectiveTenantID"] = authmw.EffectiveTenantID(r)
	}
	if _, set := data["CSRFToken"]; !set {
		data["CSRFToken"] = csrf.Token(r)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, "layout", data); err != nil {
		slog.Error("template execute failed", "page", page, "err", err)
		http.Error(w, "render error", http.StatusInternalServerError)
	}
}

// handleIndex sends the visitor to the device list (auth lands later).
// in: writer, request. out: 302 to /devices.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/devices", http.StatusFound)
}
