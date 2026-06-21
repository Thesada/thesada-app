// Package web serves the HTMX-driven dashboard. Pages are Go html/template
// rendered server-side and call pkg/service directly (not /api/v1 over HTTP).
// Tailwind CSS is delivered as a static asset built by the standalone CLI.
package web

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"reflect"
	"sort"
	"strconv"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/config"
	"thesada.app/app/pkg/csrf"
	"thesada.app/app/pkg/httpsec"
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
	cfg         *config.Config
	services        *service.Services
	mailer          *mailer.Mailer
	mqtt            *mqtt.Client
	ca              *pki.CA
	mux             *http.ServeMux
	handler         http.Handler
	templates       map[string]*template.Template
	emailHTML       map[string]*template.Template     // html variant, auto-escaped
	emailText       map[string]*texttemplate.Template // text variant, no escaping
	emailLimits     *ratelimit.Limiter
	ipLimits        *ratelimit.Limiter
	waitlistNotify  *ratelimit.Limiter
	cliRequests     *cliRequestStore
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

// handleLoginForm renders the email/password + magic link login form.
// in: writer, request. out: HTML form.
func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	data := map[string]interface{}{}
	if provs, err := s.services.OAuth.ListEnabledProvidersForLogin(r.Context()); err == nil && len(provs) > 0 {
		data["OAuthProviders"] = provs
	}
	s.render(w, r, "login.html", data)
}

// handleLoginSubmit processes login: if a password is provided, verify it and
// start a session; if the password is empty, issue a magic link and email it.
// in: writer, POST form (email, password). out: 302 to /devices on success,
// login.html with error on failure, or login.html with "check your email".
func (s *Server) handleLoginSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.PostFormValue("email"))
	password := r.PostFormValue("password")
	if email == "" {
		s.render(w, r, "login.html", map[string]interface{}{"Error": "Email is required."})
		return
	}

	if password != "" {
		u, err := s.services.Auth.VerifyPasswordAnyTenant(email, password)
		if err != nil {
			if errors.Is(err, service.ErrBadCredentials) {
				s.render(w, r, "login.html", map[string]interface{}{"Error": "Invalid email or password."})
				return
			}
			slog.Error("password verify failed", "email", email, "err", err)
			http.Error(w, "login failed", http.StatusInternalServerError)
			return
		}
		s.startSession(w, r, u, "password")
		http.Redirect(w, r, "/devices", http.StatusFound)
		return
	}

	if !s.allowMagicLink(email, clientIP(r)) {
		s.render(w, r, "login.html", map[string]interface{}{"Sent": true, "Email": email})
		return
	}
	u, err := s.services.Auth.GetUserByEmailAnyTenant(email)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			s.render(w, r, "login.html", map[string]interface{}{"Sent": true, "Email": email})
			return
		}
		slog.Error("user lookup failed", "email", email, "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	token, _, err := s.services.Auth.CreateMagicLink(u.ID)
	if err != nil {
		slog.Error("magic link create failed", "email", email, "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	link := s.cfg.BaseURL + "/login/verify?token=" + token
	textBody, htmlBody, err := s.renderEmail("login_link", map[string]interface{}{"Link": link})
	if err != nil {
		slog.Error("login email render failed", "err", err)
	} else if err := s.mailer.SendMIME(email, "Your thesada sign-in link", textBody, htmlBody); err != nil {
		slog.Error("magic link email failed", "email", email, "err", err)
	}
	s.render(w, r, "login.html", map[string]interface{}{"Sent": true, "Email": email})
}

// handleMagicLinkVerify consumes a magic link token from the URL and starts a session.
// in: writer, request with ?token=. out: 302 to /devices or login.html with error.
func (s *Server) handleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		s.render(w, r, "login.html", map[string]interface{}{"Error": "Missing link token."})
		return
	}
	u, err := s.services.Auth.ConsumeMagicLink(token)
	if err != nil {
		if errors.Is(err, service.ErrExpired) {
			s.render(w, r, "login.html", map[string]interface{}{"Error": "That link has expired. Request a new one."})
			return
		}
		if errors.Is(err, service.ErrNotFound) {
			s.render(w, r, "login.html", map[string]interface{}{"Error": "That link is invalid or already used."})
			return
		}
		slog.Error("magic link consume failed", "err", err)
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}
	s.startSession(w, r, u, "magic_link")
	http.Redirect(w, r, "/devices", http.StatusFound)
}

// handleLogout revokes the current session and clears the cookie.
// in: writer, request. out: 302 to /login.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	if c, err := r.Cookie(authmw.CookieName); err == nil && c.Value != "" {
		if err := s.services.Auth.RevokeSession(c.Value); err != nil {
			slog.Warn("session revoke failed", "err", err)
		}
	}
	authmw.ClearSessionCookie(w)
	if u != nil {
		slog.Info("auth.session.state_change",
			"from", "authenticated", "to", "anonymous",
			"user_id", u.ID, "tenant", u.TenantID)
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// startSession creates a new session row and writes the cookie on the response.
// in: writer, request, user, auth method. out: none.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, u *service.User, method string) {
	ua := r.UserAgent()
	ip := clientIP(r)
	token, expires, err := s.services.Auth.CreateSession(u.TenantID, u.ID, method, ua, ip)
	if err != nil {
		slog.Error("session create failed", "user_id", u.ID, "err", err)
		return
	}
	authmw.SetSessionCookie(w, token, expires, httpsec.RequestIsSecure(r))
	slog.Info("auth.session.state_change",
		"from", "anonymous", "to", "authenticated",
		"user_id", u.ID, "tenant", u.TenantID, "method", method)
}

// clientIP returns the best-guess remote address for the request, stripping the port.
// in: request. out: ip string or "".
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[:i]
	}
	return addr
}

// handleSignupForm renders the email-only waitlist form.
// in: writer, request. out: HTML form.
func (s *Server) handleSignupForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "signup.html", nil)
}

// handleSignupSubmit inserts the email into the waitlist and re-renders with a thank-you state.
// in: writer, POST form (email, optional note). out: HTML page with confirmation or error.
func (s *Server) handleSignupSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := r.PostFormValue("email")
	note := r.PostFormValue("note")
	if email == "" {
		s.render(w, r, "signup.html", map[string]interface{}{"Error": "Email is required."})
		return
	}
	if _, err := s.services.Auth.AddToWaitlist(bootstrapTenantID, email, note); err != nil {
		slog.Error("waitlist insert failed", "email", email, "err", err)
		s.render(w, r, "signup.html", map[string]interface{}{"Error": "Could not add to waitlist."})
		return
	}
	//  phase 1: plain-text admin notification, deduped 24h per
	// email so a user hammering signup doesn't spam the operator.
	s.notifyAdminWaitlist(email, note, clientIP(r))
	s.render(w, r, "signup.html", map[string]interface{}{"Joined": true, "Email": email})
}

// notifyAdminWaitlist emails THESADA_ADMIN_EMAIL when a new signup lands,
// deduped 24h per lowercase email via waitlistNotify. Email send runs in a
// goroutine so the form response is never blocked on SMTP. No-op if admin
// email is unset (test / dev).
// in: waitlist email, optional note, client IP. out: none.
func (s *Server) notifyAdminWaitlist(email, note, ip string) {
	if s.cfg.AdminEmail == "" {
		return
	}
	key := "signup:" + strings.ToLower(email)
	if !s.waitlistNotify.Allow(key) {
		return
	}
	go func() {
		body := "New waitlist signup on thesada-app\r\n\r\n" +
			"email: " + email + "\r\n"
		if note != "" {
			body += "note:  " + note + "\r\n"
		}
		if ip != "" {
			body += "ip:    " + ip + "\r\n"
		}
		body += "when:  " + time.Now().Format(time.RFC3339) + "\r\n"
		if err := s.mailer.Send(s.cfg.AdminEmail, "thesada: new waitlist signup - "+email, body); err != nil {
			slog.Warn("waitlist admin notify send failed", "admin", s.cfg.AdminEmail, "err", err)
		}
	}()
}

// handleDeviceList renders the tenant device table from a live DB query.
// in: writer, request. out: HTML table or empty-state.
func (s *Server) handleDeviceList(w http.ResponseWriter, r *http.Request) {
	tenantID := authmw.EffectiveTenantID(r)
	devices, err := s.services.Devices.ListByTenant(tenantID)
	if err != nil {
		slog.Error("device list failed", "err", err)
		http.Error(w, "device list failed", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "devices.html", map[string]interface{}{"Devices": devices})
}

// handleDeviceDetail renders one device with its recent heartbeats and alerts.
// in: writer, request with path value "id" (UUID). out: HTML page or 404.
func (s *Server) handleDeviceDetail(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	// Super-admins follow links out of /admin/devices that span tenants, so
	// they bypass the tenant scope on the lookup. Tenant users stay scoped to
	// their own (or impersonated) tenant.
	me := authmw.CurrentUser(r)
	var device *service.Device
	if me != nil && me.IsSuperAdmin {
		device, err = s.services.Devices.GetByIDAny(r.Context(), id)
	} else {
		device, err = s.services.Devices.GetByID(id, authmw.EffectiveTenantID(r))
	}
	if err != nil {
		slog.Error("device get failed", "id", id, "err", err)
		http.Error(w, "device get failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}
	latest, err := s.services.Telemetry.LatestPerMetric(r.Context(), device.TenantID, id)
	if err != nil {
		slog.Error("latest sensors fetch failed", "id", id, "err", err)
		http.Error(w, "sensors fetch failed", http.StatusInternalServerError)
		return
	}
	telemetry, err := s.services.Telemetry.RecentTelemetry(r.Context(), device.TenantID, id, "", 50)
	if err != nil {
		slog.Error("telemetry fetch failed", "id", id, "err", err)
		http.Error(w, "telemetry fetch failed", http.StatusInternalServerError)
		return
	}
	alerts, err := s.services.Alerts.RecentAlerts(r.Context(), device.TenantID, id, "", 25)
	if err != nil {
		slog.Error("alerts fetch failed", "id", id, "err", err)
		http.Error(w, "alerts fetch failed", http.StatusInternalServerError)
		return
	}
	// Build a sorted list of numeric metric names for the chart selector.
	// A metric is "numeric" if its latest row has a non-null value_num.
	// Text metrics (battery/charging, wifi/ip, etc) are skipped - caggs
	// exclude them and the chart has nothing to show.
	numericMetrics := make([]string, 0, len(latest))
	for _, t := range latest {
		if t.ValueNum != nil {
			numericMetrics = append(numericMetrics, t.Metric)
		}
	}
	sort.Strings(numericMetrics)

	// If a super-admin landed here from /admin/devices, send the back link
	// there instead of the tenant-scoped /devices list. Avoids the
	// "Admin -> Devices -> click a row -> back -> wrong page" surprise.
	backHref := "/devices"
	backLabel := "All devices"
	if u := authmw.CurrentUser(r); u != nil && u.IsSuperAdmin {
		ref := r.Referer()
		if strings.Contains(ref, "/admin/devices") && !strings.Contains(ref, "/admin/devices/") {
			backHref = "/admin/devices"
			backLabel = "Admin devices"
		}
	}

	s.render(w, r, "device-detail.html", map[string]interface{}{
		"Device":         device,
		"Latest":         latest,
		"Telemetry":      telemetry,
		"Alerts":         alerts,
		"NumericMetrics": numericMetrics,
		"BackHref":       backHref,
		"BackLabel":      backLabel,
	})
}

// handleDeviceChartJSON returns a bucketed time-series for one metric on
// one device in JSON form. Used by the Chart.js client on device-detail.
// Tenant-scoped via EffectiveTenantID so a super-admin impersonating a
// different tenant cannot read another tenant's history.
// in: writer, request (path {id}, query metric, range). out: JSON series.
func (s *Server) handleDeviceChartJSON(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	me := authmw.CurrentUser(r)
	var device *service.Device
	if me != nil && me.IsSuperAdmin {
		device, err = s.services.Devices.GetByIDAny(r.Context(), id)
	} else {
		device, err = s.services.Devices.GetByID(id, authmw.EffectiveTenantID(r))
	}
	if err != nil {
		slog.Error("chart device get failed", "id", id, "err", err)
		http.Error(w, "device get failed", http.StatusInternalServerError)
		return
	}
	if device == nil {
		http.NotFound(w, r)
		return
	}
	metric := r.URL.Query().Get("metric")
	rangeName := r.URL.Query().Get("range")
	if rangeName == "" {
		rangeName = "24h"
	}
	series, err := s.services.Telemetry.History(r.Context(), device.TenantID, id, metric, rangeName)
	if err != nil {
		if errors.Is(err, service.ErrInvalidRange) {
			http.Error(w, "invalid range or metric", http.StatusBadRequest)
			return
		}
		slog.Error("chart history fetch failed", "id", id, "metric", metric, "range", rangeName, "err", err)
		http.Error(w, "history fetch failed", http.StatusInternalServerError)
		return
	}
	// Shape for Chart.js: parallel arrays keep the JS side small.
	labels := make([]string, 0, len(series.Points))
	avg := make([]*float64, 0, len(series.Points))
	minV := make([]*float64, 0, len(series.Points))
	maxV := make([]*float64, 0, len(series.Points))
	for _, p := range series.Points {
		labels = append(labels, p.T.UTC().Format(time.RFC3339))
		avg = append(avg, p.Avg)
		minV = append(minV, p.Min)
		maxV = append(maxV, p.Max)
	}
	resp := map[string]interface{}{
		"metric": series.Metric,
		"range":  series.Range,
		"labels": labels,
		"avg":    avg,
		"min":    minV,
		"max":    maxV,
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		slog.Error("chart json encode failed", "err", err)
	}
}

// handleSettingsForm renders the account settings page with a set/change password form.
// in: writer, request (auth required). out: HTML form with HasPassword flag.
func (s *Server) handleSettingsForm(w http.ResponseWriter, r *http.Request) {
	u := authmw.CurrentUser(r)
	has, err := s.services.Auth.HasPassword(u.TenantID, u.ID)
	if err != nil {
		slog.Error("has-password query failed", "user_id", u.ID, "err", err)
		http.Error(w, "settings load failed", http.StatusInternalServerError)
		return
	}
	subs, _ := s.services.Alerts.ListSubscriptions(r.Context(), u.TenantID, u.ID)
	savedSection := r.URL.Query().Get("saved")
	identities, _ := s.services.OAuth.ListIdentitiesForUser(r.Context(), u.TenantID, u.ID)
	providers, _ := s.services.OAuth.ListEnabledProvidersForTenant(r.Context(), u.TenantID)
	s.render(w, r, "settings.html", map[string]interface{}{
		"HasPassword":     has,
		"Subscriptions":   subs,
		"SavedSection":    savedSection,
		"OAuthIdentities": identities,
		"OAuthProviders":  providers,
		"OAuthError":      r.URL.Query().Get("err"),
	})
}

// handleSettingsProfile updates the user's display name.
// in: writer, POST form (display_name). out: redirect to settings.
func (s *Server) handleSettingsProfile(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	displayName := strings.TrimSpace(r.PostFormValue("display_name"))
	telegramChatID := strings.TrimSpace(r.PostFormValue("telegram_chat_id"))
	if err := s.services.Auth.UpdateDisplayName(u.TenantID, u.ID, displayName); err != nil {
		slog.Error("update display name failed", "user_id", u.ID, "err", err)
	}
	if err := s.services.Auth.UpdateTelegramChatID(u.TenantID, u.ID, telegramChatID); err != nil {
		slog.Error("update telegram chat_id failed", "user_id", u.ID, "err", err)
	}
	http.Redirect(w, r, "/settings?saved=profile", http.StatusSeeOther)
}

// handleSettingsNotificationAdd creates a new alert subscription.
// in: writer, POST form (channel, min_severity). out: redirect to settings.
func (s *Server) handleSettingsNotificationAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	channel := r.PostFormValue("channel")
	severity := r.PostFormValue("min_severity")
	if channel != "email" && channel != "telegram" {
		http.Error(w, "invalid channel", http.StatusBadRequest)
		return
	}
	if severity != "info" && severity != "warn" && severity != "crit" {
		severity = "warn"
	}
	if err := s.services.Alerts.CreateSubscription(r.Context(), u.TenantID, u.ID, nil, channel, severity); err != nil {
		slog.Error("create subscription failed", "user_id", u.ID, "err", err)
	}
	http.Redirect(w, r, "/settings?saved=notifications", http.StatusSeeOther)
}

// handleSettingsNotificationDelete removes an alert subscription.
// in: writer, POST form (sub_id). out: redirect to settings.
func (s *Server) handleSettingsNotificationDelete(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	subID, err := uuid.Parse(r.PostFormValue("sub_id"))
	if err != nil {
		http.Error(w, "invalid sub_id", http.StatusBadRequest)
		return
	}
	if err := s.services.Alerts.DeleteSubscription(r.Context(), u.TenantID, subID, u.ID); err != nil {
		slog.Error("delete subscription failed", "user_id", u.ID, "sub_id", subID, "err", err)
	}
	http.Redirect(w, r, "/settings?saved=notifications", http.StatusSeeOther)
}

// handleSettingsPassword validates the POSTed new password and stores a bcrypt hash.
// Enforces min length 10 and a matching confirm field. Re-renders with error or success flash.
// in: writer, POST form (password, confirm). out: HTML page.
func (s *Server) handleSettingsPassword(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	u := authmw.CurrentUser(r)
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")
	has, _ := s.services.Auth.HasPassword(u.TenantID, u.ID)
	data := map[string]interface{}{"HasPassword": has}
	if len(password) < 10 {
		data["Error"] = "Password must be at least 10 characters."
		s.render(w, r, "settings.html", data)
		return
	}
	if password != confirm {
		data["Error"] = "Passwords do not match."
		s.render(w, r, "settings.html", data)
		return
	}
	if err := s.services.Auth.SetPassword(u.TenantID, u.ID, password); err != nil {
		slog.Error("set password failed", "user_id", u.ID, "err", err)
		data["Error"] = "Could not save password."
		s.render(w, r, "settings.html", data)
		return
	}
	data["HasPassword"] = true
	data["Saved"] = true
	s.render(w, r, "settings.html", data)
}

// allowMagicLink consults the per-email and per-IP sliding-window limiters
// and returns false when either bucket is full. Callers treat a false result
// as a silent drop: the user still sees "check your email" so the endpoint
// does not leak which addresses are known or rate-limited.
// in: email, client ip. out: true if both limiters have headroom.
func (s *Server) allowMagicLink(email, ip string) bool {
	if !s.emailLimits.Allow("email:" + strings.ToLower(email)) {
		slog.Warn("magic link email rate-limited", "email", email)
		return false
	}
	if ip != "" && !s.ipLimits.Allow("ip:"+ip) {
		slog.Warn("magic link ip rate-limited", "ip", ip)
		return false
	}
	return true
}

// handleForgotForm renders the "enter your email" password-reset request page.
// in: writer, request. out: HTML form.
func (s *Server) handleForgotForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "forgot.html", nil)
}

// handleForgotSubmit issues a password reset token and emails the link.
// Always renders the same "check your email" confirmation regardless of
// whether the address exists, so the form cannot be used to enumerate users.
// Rate-limited by email and source IP.
// in: writer, POST form (email). out: HTML confirmation page.
func (s *Server) handleForgotSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.PostFormValue("email"))
	if email == "" {
		s.render(w, r, "forgot.html", map[string]interface{}{"Error": "Email is required."})
		return
	}
	confirm := map[string]interface{}{"Sent": true, "Email": email}
	if !s.allowMagicLink(email, clientIP(r)) {
		s.render(w, r, "forgot.html", confirm)
		return
	}
	u, err := s.services.Auth.GetUserByEmailAnyTenant(email)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			s.render(w, r, "forgot.html", confirm)
			return
		}
		slog.Error("forgot user lookup failed", "email", email, "err", err)
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	token, _, err := s.services.Auth.CreateResetLink(u.ID)
	if err != nil {
		slog.Error("reset link create failed", "email", email, "err", err)
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	link := s.cfg.BaseURL + "/reset-password?token=" + token
	textBody, htmlBody, err := s.renderEmail("reset_link", map[string]interface{}{"Link": link})
	if err != nil {
		slog.Error("reset email render failed", "err", err)
	} else if err := s.mailer.SendMIME(email, "Your thesada password reset link", textBody, htmlBody); err != nil {
		slog.Error("reset email failed", "email", email, "err", err)
	}
	s.render(w, r, "forgot.html", confirm)
}

// handleResetForm renders the "set a new password" form after validating the
// reset token. The token is not consumed here so the user can still submit
// the form; consumption happens in handleResetSubmit on success.
// in: writer, request with ?token=. out: HTML form or error page.
func (s *Server) handleResetForm(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		s.render(w, r, "reset.html", map[string]interface{}{"Error": "Missing reset token."})
		return
	}
	if _, _, err := s.services.Auth.ConsumeResetLink(token); err != nil {
		s.render(w, r, "reset.html", map[string]interface{}{"Error": resetErrMessage(err)})
		return
	}
	s.render(w, r, "reset.html", map[string]interface{}{"Token": token})
}

// handleResetSubmit revalidates the token, stores the new bcrypt password
// hash, and marks the token consumed. On success the user is redirected to
// /login so they can sign in with the new password.
// in: writer, POST form (token, password, confirm). out: redirect or error.
func (s *Server) handleResetSubmit(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	token := r.PostFormValue("token")
	password := r.PostFormValue("password")
	confirm := r.PostFormValue("confirm")
	if token == "" {
		s.render(w, r, "reset.html", map[string]interface{}{"Error": "Missing reset token."})
		return
	}
	u, tokenID, err := s.services.Auth.ConsumeResetLink(token)
	if err != nil {
		s.render(w, r, "reset.html", map[string]interface{}{"Error": resetErrMessage(err)})
		return
	}
	if len(password) < 10 {
		s.render(w, r, "reset.html", map[string]interface{}{"Token": token, "Error": "Password must be at least 10 characters."})
		return
	}
	if password != confirm {
		s.render(w, r, "reset.html", map[string]interface{}{"Token": token, "Error": "Passwords do not match."})
		return
	}
	if err := s.services.Auth.SetPassword(u.TenantID, u.ID, password); err != nil {
		slog.Error("reset set password failed", "user_id", u.ID, "err", err)
		http.Error(w, "reset failed", http.StatusInternalServerError)
		return
	}
	if err := s.services.Auth.MarkResetConsumed(tokenID); err != nil {
		slog.Warn("reset token mark consumed failed", "err", err)
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

// resetErrMessage maps an auth service error to a user-visible reset-page string.
// in: error from ConsumeResetLink. out: message safe to show to the caller.
func resetErrMessage(err error) string {
	if errors.Is(err, service.ErrExpired) {
		return "That reset link has expired. Request a new one."
	}
	return "That reset link is invalid or already used."
}

// handleAlertList renders the most recent alerts across all devices in the tenant.
// in: writer, request. out: HTML list.
func (s *Server) handleAlertList(w http.ResponseWriter, r *http.Request) {
	tenantID := authmw.EffectiveTenantID(r)
	rows, err := s.services.Alerts.RecentByTenant(r.Context(), tenantID, 100)
	if err != nil {
		slog.Error("alerts fetch failed", "err", err)
		http.Error(w, "alerts fetch failed", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "alerts.html", map[string]interface{}{"Alerts": rows})
}

// MetricGroup is a folder in the Latest-sensors table: one metric-prefix
// bucket (e.g. "battery/") holding every row whose metric starts with that
// prefix. Ungrouped metrics (no slash) go into a single Name="" group that
// the template renders as a flat flush-left block.
type MetricGroup struct {
	Name string // "battery", "heap", "wifi", "temperature", "" for ungrouped
	Rows []any  // device_telemetry rows, reflection-friendly
}

// funcMap holds template helpers for safely formatting nullable DB columns
// and for the metric-prefix folder grouping on the device detail page.
var funcMap = template.FuncMap{
	"deref":            derefString,
	"derefOrDash":      derefStringOrDash,
	"derefIntOrDash":   derefIntOrDash,
	"derefInt64OrDash": derefInt64OrDash,
	"timeOrDash":       timeOrDash,
	"fmtTime":          fmtTime,
	"uptimeLive":       uptimeLive,
	"telemetryValue":   telemetryValueText,
	"metricLeaf":       metricLeaf,
	"groupLatest":      groupLatestByPrefix,
}

// metricLeaf returns the part of a metric name after the first slash, or
// the whole metric if it has no slash. Used inside the folder body to
// show "percent" instead of "battery/percent".
// in: full metric string. out: leaf segment for display.
func metricLeaf(metric string) string {
	if i := strings.Index(metric, "/"); i >= 0 {
		return metric[i+1:]
	}
	return metric
}

// groupLatestByPrefix buckets a flat device_telemetry slice by the first
// path segment of the metric name. Rows inside each bucket stay in the
// order the query returned them (already sorted by metric name because
// the SQL uses DISTINCT ON ... ORDER BY metric). Ungrouped rows collect
// into a single MetricGroup with Name="".
// in: telemetry slice from LatestPerMetric. out: []MetricGroup sorted by Name.
func groupLatestByPrefix(latest any) []MetricGroup {
	rv := reflect.ValueOf(latest)
	if !rv.IsValid() || rv.Kind() != reflect.Slice {
		return nil
	}
	buckets := make(map[string][]any)
	for i := 0; i < rv.Len(); i++ {
		row := rv.Index(i).Interface()
		metric := reflect.ValueOf(row).FieldByName("Metric").String()
		prefix := ""
		if j := strings.Index(metric, "/"); j >= 0 {
			prefix = metric[:j]
		}
		buckets[prefix] = append(buckets[prefix], row)
	}
	names := make([]string, 0, len(buckets))
	for n := range buckets {
		names = append(names, n)
	}
	sort.Strings(names)
	out := make([]MetricGroup, 0, len(names))
	for _, n := range names {
		out = append(out, MetricGroup{Name: n, Rows: buckets[n]})
	}
	return out
}

// telemetryValueText renders a device_telemetry row's value column as a
// short human string. Numeric metrics print with up to 3 decimals trimmed,
// text metrics fall back to value_text, and rows with neither show "-".
// in: telemetry row (passed as any so the unexported struct type still
// matches via reflection from html/template).
// out: display string for the table cell.
func telemetryValueText(row any) string {
	rv := reflect.ValueOf(row)
	if !rv.IsValid() {
		return "-"
	}
	if rv.Kind() == reflect.Ptr {
		rv = rv.Elem()
	}
	num := rv.FieldByName("ValueNum")
	if num.IsValid() && !num.IsNil() {
		f := num.Elem().Float()
		s := strconv.FormatFloat(f, 'f', -1, 64)
		metric := ""
		if mf := rv.FieldByName("Metric"); mf.IsValid() {
			metric = mf.String()
		}
		return s + metricUnit(metric)
	}
	txt := rv.FieldByName("ValueText")
	if txt.IsValid() && !txt.IsNil() {
		return txt.Elem().String()
	}
	return "-"
}

// metricUnit returns a display unit suffix for a telemetry metric path.
// Metric paths look like "sensor/temperature/name" or "sensor/humidity/name".
// in: metric path. out: unit string with leading space, or "".
func metricUnit(metric string) string {
	m := strings.ToLower(metric)
	switch {
	case strings.Contains(m, "/temperature"):
		return " \u00B0"
	case strings.Contains(m, "/humidity"):
		return " %"
	case strings.Contains(m, "/current"):
		return " A"
	case strings.Contains(m, "/voltage"):
		return " V"
	case strings.Contains(m, "/power"):
		return " W"
	case strings.Contains(m, "/percent"):
		return " %"
	case strings.Contains(m, "/rssi"):
		return " dBm"
	default:
		return ""
	}
}

// derefString returns the pointed-to string or "" if nil.
// in: *string. out: string (empty when nil).
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// derefStringOrDash returns the pointed-to string or "-" if nil/empty.
// in: *string. out: visible string.
func derefStringOrDash(s *string) string {
	if s == nil || *s == "" {
		return "-"
	}
	return *s
}

// derefIntOrDash returns the int as text or "-" if nil.
// in: *int. out: text representation.
func derefIntOrDash(v *int) string {
	if v == nil {
		return "-"
	}
	return intToString(int64(*v))
}

// derefInt64OrDash returns the int64 as text or "-" if nil.
// in: *int64. out: text representation.
func derefInt64OrDash(v *int64) string {
	if v == nil {
		return "-"
	}
	return intToString(*v)
}

// timeOrDash formats a time pointer or returns "-" if nil.
// in: *time.Time. out: ISO timestamp or dash.
func timeOrDash(t *time.Time) template.HTML {
	if t == nil {
		return "-"
	}
	return fmtTime(*t)
}

// fmtTime wraps a time.Time in a <time> element with an RFC3339 datetime
// attribute. The JS in layout.html converts these to the browser's local
// timezone on page load.
// in: time.Time. out: template.HTML with <time> element.
func fmtTime(t time.Time) template.HTML {
	iso := t.UTC().Format(time.RFC3339)
	display := t.Format("2006-01-02 15:04:05")
	return template.HTML(`<time datetime="` + iso + `">` + display + `</time>`)
}

// intToString converts an int64 to base-10 text.
// in: int64. out: decimal string.
func intToString(v int64) string {
	return strconv.FormatInt(v, 10)
}

// uptimeLive renders a human-readable "live" uptime from the last reported
// uptime sample plus wall-clock elapsed since the sample arrived. Returns
// "-" if either input is nil. Appends "(stale)" when the last sample is
// more than 15 min old so the table flags devices that stopped reporting.
// in: last uptime seconds from device, time that sample was received.
// out: "Xd Yh Zm" string.
func uptimeLive(secs *int64, at *time.Time) string {
	if secs == nil || at == nil {
		return "-"
	}
	elapsed := int64(time.Since(*at).Seconds())
	total := *secs + elapsed
	if total < 0 {
		total = 0
	}
	d := total / 86400
	h := (total % 86400) / 3600
	m := (total % 3600) / 60
	var s string
	switch {
	case d > 0:
		s = fmt.Sprintf("%dd %dh %dm", d, h, m)
	case h > 0:
		s = fmt.Sprintf("%dh %dm", h, m)
	default:
		s = fmt.Sprintf("%dm", m)
	}
	if elapsed > 15*60 {
		s += " (stale)"
	}
	return s
}
