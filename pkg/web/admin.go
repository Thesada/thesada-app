// Super-admin handlers for the /admin route tree. All handlers here assume
// they are wrapped in authmw.RequireSuperAdmin - they do not re-check the
// super-admin flag on every call.
package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/service"
)

// adminTenantRow is the view-model for a single row in the admin tenant list.
// Counts are computed by the handler so the template stays dumb.
type adminTenantRow struct {
	Tenant           service.Tenant
	UserCount        int
	DeviceCount      int
	IsDefault        bool
	IsCurrent        bool // caller's effective tenant
	CrossTenantRead  bool // mqtt_cross_tenant_read on this tenant - paired devices subscribe across all tenants
}

// handleAdminIndex renders the super-admin dashboard: tenant count, user
// count, device count, pending-waitlist count, and a link list into the
// subpages.
// in: writer, request. out: HTML page.
func (s *Server) handleAdminIndex(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.services.Tenants.List()
	if err != nil {
		slog.Error("admin index list failed", "err", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	var totalUsers, totalDevices int
	for _, t := range tenants {
		u, d := s.countTenantUsersDevices(t.ID)
		totalUsers += u
		totalDevices += d
	}
	pendingWaitlist, err := s.services.Auth.CountPendingWaitlist()
	if err != nil {
		slog.Warn("admin index waitlist count failed", "err", err)
		pendingWaitlist = 0
	}
	s.render(w, r, "admin-index.html", map[string]interface{}{
		"TenantCount":     len(tenants),
		"TotalUsers":      totalUsers,
		"TotalDevices":    totalDevices,
		"PendingWaitlist": pendingWaitlist,
		"MultiTenantMode": s.services.Settings.GetBool("default", "multi_tenant_mode", false),
	})
}

// handleAdminTenants renders the tenant list with per-tenant user + device
// counts and inline create/delete/impersonate actions.
// in: writer, request. out: HTML page.
func (s *Server) handleAdminTenants(w http.ResponseWriter, r *http.Request) {
	tenants, err := s.services.Tenants.List()
	if err != nil {
		slog.Error("admin tenant list failed", "err", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	effective := authmw.EffectiveTenantID(r)
	rows := make([]adminTenantRow, 0, len(tenants))
	for _, t := range tenants {
		uc, dc := s.countTenantUsersDevices(t.ID)
		rows = append(rows, adminTenantRow{
			Tenant:          t,
			UserCount:       uc,
			DeviceCount:     dc,
			IsDefault:       t.ID == "default",
			IsCurrent:       t.ID == effective,
			CrossTenantRead: s.services.Settings.GetBool(t.ID, "mqtt_cross_tenant_read", t.ID == "default"),
		})
	}
	s.render(w, r, "admin-tenants.html", map[string]interface{}{
		"Rows":            rows,
		"MultiTenantMode": s.services.Settings.GetBool("default", "multi_tenant_mode", false),
	})
}

// handleAdminTenantCreate processes the create-tenant form. App-side slug
// validation mirrors the db CHECK so the friendly error lands on the form
// page rather than a 500 from the db.
// in: writer, POST form (slug, display_name). out: 302 to /admin/tenants or
// /admin/tenants with inline error.
func (s *Server) handleAdminTenantCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	slug := strings.ToLower(strings.TrimSpace(r.PostFormValue("slug")))
	displayName := strings.TrimSpace(r.PostFormValue("display_name"))
	if _, err := s.services.Tenants.Create(slug, displayName); err != nil {
		switch {
		case errors.Is(err, service.ErrInvalidSlug),
			errors.Is(err, service.ErrReservedSlug),
			errors.Is(err, service.ErrSlugTaken):
			s.renderAdminTenantsWithError(w, r, err.Error())
			return
		default:
			slog.Error("admin tenant create failed", "slug", slug, "err", err)
			http.Error(w, "create failed", http.StatusInternalServerError)
			return
		}
	}
	http.Redirect(w, r, "/admin/tenants", http.StatusFound)
}

// handleAdminTenantDelete processes a tenant delete action. Guards against
// removing the default tenant and against a super-admin deleting the tenant
// they are currently impersonating (which would strand their view).
// in: writer, POST to /admin/tenants/{slug}/delete. out: 302 to /admin/tenants.
func (s *Server) handleAdminTenantDelete(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	effective := authmw.EffectiveTenantID(r)
	if err := s.services.Tenants.Delete(slug, effective); err != nil {
		if errors.Is(err, service.ErrTenantProtected) {
			s.renderAdminTenantsWithError(w, r, "That tenant cannot be deleted (default or your current tenant).")
			return
		}
		slog.Error("admin tenant delete failed", "slug", slug, "err", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/tenants", http.StatusFound)
}

// handleAdminImpersonate sets the impersonated tenant on the caller's
// session so subsequent page loads scope every query through the target
// tenant. Anyone who reaches this handler is already a super-admin by
// middleware contract.
// in: writer, POST to /admin/impersonate/{slug}. out: 302 to /devices.
func (s *Server) handleAdminImpersonate(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if !s.services.Tenants.ExistsBySlug(slug) {
		http.NotFound(w, r)
		return
	}
	sess := authmw.CurrentSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := s.services.Auth.SetImpersonation(sess.ID, slug); err != nil {
		slog.Error("set impersonation failed", "session", sess.ID, "slug", slug, "err", err)
		http.Error(w, "impersonate failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/devices", http.StatusFound)
}

// handleAdminImpersonateClear drops any impersonation on the caller's
// session, returning their view to their own tenant.
// in: writer, POST /admin/impersonate. out: 302 to /admin.
func (s *Server) handleAdminImpersonateClear(w http.ResponseWriter, r *http.Request) {
	sess := authmw.CurrentSession(r)
	if sess == nil {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	if err := s.services.Auth.ClearImpersonation(sess.ID); err != nil {
		slog.Error("clear impersonation failed", "session", sess.ID, "err", err)
		http.Error(w, "clear failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin", http.StatusFound)
}

// renderAdminTenantsWithError re-runs the list query and renders the tenant
// list page with an inline error banner. Used by the create and delete
// handlers when a soft validation error should keep the user on the same
// page instead of 500ing.
// in: writer, request, error message. out: HTML page.
func (s *Server) renderAdminTenantsWithError(w http.ResponseWriter, r *http.Request, msg string) {
	tenants, err := s.services.Tenants.List()
	if err != nil {
		slog.Error("admin tenant list (error path) failed", "err", err)
		http.Error(w, "list failed", http.StatusInternalServerError)
		return
	}
	effective := authmw.EffectiveTenantID(r)
	rows := make([]adminTenantRow, 0, len(tenants))
	for _, t := range tenants {
		uc, dc := s.countTenantUsersDevices(t.ID)
		rows = append(rows, adminTenantRow{
			Tenant:          t,
			UserCount:       uc,
			DeviceCount:     dc,
			IsDefault:       t.ID == "default",
			IsCurrent:       t.ID == effective,
			CrossTenantRead: s.services.Settings.GetBool(t.ID, "mqtt_cross_tenant_read", t.ID == "default"),
		})
	}
	s.render(w, r, "admin-tenants.html", map[string]interface{}{
		"Rows":            rows,
		"Error":           msg,
		"MultiTenantMode": s.services.Settings.GetBool("default", "multi_tenant_mode", false),
	})
}

// ---------------------------------------------------------------------------
// Waitlist -> user conversion
// ---------------------------------------------------------------------------

// adminWaitlistRow is the view-model for one pending waitlist entry with
// the full tenant list pre-attached so the template can render the target
// picker without an extra service call per row.
type adminWaitlistRow struct {
	Entry   service.WaitlistEntry
	Tenants []service.Tenant
}

// handleAdminWaitlist lists pending waitlist rows grouped by tenant and
// renders each with a target-tenant picker, optional "tenant admin"
// checkbox, and a convert button.
// in: writer, request. out: HTML page.
func (s *Server) handleAdminWaitlist(w http.ResponseWriter, r *http.Request) {
	pending, err := s.services.Auth.ListPendingWaitlist()
	if err != nil {
		slog.Error("admin waitlist list failed", "err", err)
		http.Error(w, "waitlist list failed", http.StatusInternalServerError)
		return
	}
	tenants, err := s.services.Tenants.List()
	if err != nil {
		slog.Error("admin waitlist tenants load failed", "err", err)
		http.Error(w, "tenants list failed", http.StatusInternalServerError)
		return
	}
	rows := make([]adminWaitlistRow, 0, len(pending))
	for _, e := range pending {
		rows = append(rows, adminWaitlistRow{Entry: e, Tenants: tenants})
	}
	s.render(w, r, "admin-waitlist.html", map[string]interface{}{
		"Rows":    rows,
		"Pending": len(pending),
	})
}

// handleAdminWaitlistConvert creates a user from a waitlist entry, marks
// the row converted, and fires a password-reset link email so the user can
// set their initial password via the existing reset flow.
// in: writer, POST form (target_tenant, is_admin). out: 302 back to list.
func (s *Server) handleAdminWaitlistConvert(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	target := strings.TrimSpace(r.PostFormValue("target_tenant"))
	isAdmin := r.PostFormValue("is_admin") == "on"
	u, err := s.services.Auth.ConvertWaitlistEntry(id, target, isAdmin)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("admin waitlist convert failed", "waitlist_id", id, "err", err)
		http.Redirect(w, r, "/admin/waitlist?error=convert+failed", http.StatusFound)
		return
	}
	// Fire a password-reset link email so the new user can set their
	// initial password. Best-effort: log and keep going if SMTP fails -
	// the admin can re-send from /admin later.
	token, _, err := s.services.Auth.CreateResetLink(u.ID)
	if err != nil {
		slog.Warn("admin waitlist reset link create failed", "user_id", u.ID, "err", err)
	} else {
		link := s.cfg.BaseURL + "/reset-password?token=" + token
		textBody, htmlBody, rerr := s.renderEmail("reset_link", map[string]interface{}{"Link": link})
		if rerr != nil {
			slog.Warn("admin waitlist reset email render failed", "err", rerr)
		} else if serr := s.mailer.SendMIME(u.Email, "Your thesada password reset link", textBody, htmlBody); serr != nil {
			slog.Warn("admin waitlist reset email send failed", "user_id", u.ID, "err", serr)
		}
	}
	slog.Info("admin waitlist convert ok", "user_id", u.ID, "email", u.Email, "tenant", u.TenantID)
	http.Redirect(w, r, "/admin/waitlist?ok=converted", http.StatusFound)
}

// handleAdminWaitlistDelete removes a pending waitlist entry.
// in: writer, request with {id} path param + csrf. out: redirect to waitlist.
func (s *Server) handleAdminWaitlistDelete(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.services.Auth.DeleteWaitlistEntry(id); err != nil {
		if errors.Is(err, service.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("admin waitlist delete failed", "waitlist_id", id, "err", err)
		http.Redirect(w, r, "/admin/waitlist?error=delete+failed", http.StatusFound)
		return
	}
	slog.Info("admin waitlist delete ok", "waitlist_id", id)
	http.Redirect(w, r, "/admin/waitlist?ok=deleted", http.StatusFound)
}

// countTenantUsersDevices returns the user count and device count for a
// single tenant. Best-effort; errors are logged and counted as zero so the
// admin dashboard still renders when one sub-query fails.
// in: tenant slug. out: user_count, device_count.
func (s *Server) countTenantUsersDevices(tenantID string) (int, int) {
	users, devices, err := s.services.Tenants.CountMembers(tenantID)
	if err != nil {
		slog.Warn("tenant count failed", "tenant", tenantID, "err", err)
		return 0, 0
	}
	return users, devices
}

// ---------------------------------------------------------------------------
// Tenant user management
// ---------------------------------------------------------------------------

// handleAdminTenantUsers lists users within one tenant + a create form.
// in: writer, request with path {slug}. out: HTML page.
func (s *Server) handleAdminTenantUsers(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	tenant, err := s.services.Tenants.Get(slug)
	if err != nil {
		if errors.Is(err, service.ErrNotFound) {
			http.NotFound(w, r)
			return
		}
		slog.Error("admin tenant lookup failed", "slug", slug, "err", err)
		http.Error(w, "tenant lookup failed", http.StatusInternalServerError)
		return
	}
	users, err := s.services.Auth.ListUsersByTenant(slug)
	if err != nil {
		slog.Error("admin tenant users list failed", "slug", slug, "err", err)
		http.Error(w, "users list failed", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "admin-tenant-users.html", map[string]interface{}{
		"Tenant":          tenant,
		"Users":           users,
		"Me":              authmw.CurrentUser(r),
		"CrossTenantRead": s.services.Settings.GetBool(slug, "mqtt_cross_tenant_read", slug == "default"),
	})
}

// handleAdminTenantUserCreate inserts a new user into the given tenant.
// in: writer, POST form (email, display_name, is_admin). out: 302 back.
func (s *Server) handleAdminTenantUserCreate(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	email := strings.TrimSpace(r.PostFormValue("email"))
	displayName := strings.TrimSpace(r.PostFormValue("display_name"))
	isAdmin := r.PostFormValue("is_admin") == "on"
	if email == "" {
		http.Redirect(w, r, "/admin/tenants/"+slug+"/users?error=email+required", http.StatusFound)
		return
	}
	if _, err := s.services.Auth.CreateUser(slug, email, displayName, isAdmin); err != nil {
		slog.Error("admin user create failed", "slug", slug, "email", email, "err", err)
		http.Redirect(w, r, "/admin/tenants/"+slug+"/users?error=create+failed", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/tenants/"+slug+"/users", http.StatusFound)
}

// handleAdminTenantUserToggle flips is_admin on a user in a tenant.
// in: writer, POST to /admin/tenants/{slug}/users/{user_id}/toggle-admin. out: 302.
func (s *Server) handleAdminTenantUserToggle(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	uid, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if _, err := s.services.Auth.ToggleAdmin(slug, uid); err != nil {
		slog.Error("admin user toggle failed", "user", uid, "err", err)
		http.Error(w, "toggle failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/tenants/"+slug+"/users", http.StatusFound)
}

// handleAdminTenantUserDelete removes a user. Guards: cannot delete self,
// cannot delete another super-admin (super rows are platform-critical).
// in: writer, POST to .../delete. out: 302.
func (s *Server) handleAdminTenantUserDelete(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	uid, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	me := authmw.CurrentUser(r)
	if me != nil && me.ID == uid {
		http.Redirect(w, r, "/admin/tenants/"+slug+"/users?error=cannot+delete+self", http.StatusFound)
		return
	}
	if err := s.services.Auth.DeleteUser(slug, uid); err != nil {
		if errors.Is(err, service.ErrSuperAdminProtected) {
			http.Redirect(w, r, "/admin/tenants/"+slug+"/users?error=cannot+delete+super-admin", http.StatusFound)
			return
		}
		slog.Error("admin user delete failed", "user", uid, "err", err)
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/tenants/"+slug+"/users", http.StatusFound)
}

// handleAdminTenantUserEdit renders the edit form for a single user.
// in: writer, GET /admin/tenants/{slug}/users/{user_id}/edit. out: HTML page.
func (s *Server) handleAdminTenantUserEdit(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	uid, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	tenant, err := s.services.Tenants.Get(slug)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	u, err := s.services.Auth.GetUserByID(slug, uid)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	s.render(w, r, "admin-tenant-user-edit.html", map[string]interface{}{
		"Tenant":   tenant,
		"EditUser": u,
		"Me":       authmw.CurrentUser(r),
	})
}

// handleAdminTenantUserUpdate saves display_name + is_admin changes.
// in: writer, POST /admin/tenants/{slug}/users/{user_id}/edit. out: 302.
func (s *Server) handleAdminTenantUserUpdate(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	uid, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	displayName := strings.TrimSpace(r.PostFormValue("display_name"))
	isAdmin := r.PostFormValue("is_admin") == "on"
	if err := s.services.Auth.UpdateUser(slug, uid, displayName, isAdmin); err != nil {
		slog.Error("admin user update failed", "user", uid, "err", err)
		http.Error(w, "update failed", http.StatusInternalServerError)
		return
	}
	slog.Info("admin user updated", "user_id", uid, "display_name", displayName, "is_admin", isAdmin)
	http.Redirect(w, r, "/admin/tenants/"+slug+"/users", http.StatusFound)
}

// handleAdminTenantUserSendReset creates a reset link and emails it to the user.
// in: writer, POST /admin/tenants/{slug}/users/{user_id}/send-reset. out: 302.
func (s *Server) handleAdminTenantUserSendReset(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	uid, err := uuid.Parse(r.PathValue("user_id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	u, err := s.services.Auth.GetUserByID(slug, uid)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	token, _, err := s.services.Auth.CreateResetLink(uid)
	if err != nil {
		slog.Error("admin send-reset link create failed", "user_id", uid, "err", err)
		http.Redirect(w, r, "/admin/tenants/"+slug+"/users/"+uid.String()+"/edit?error=link+failed", http.StatusFound)
		return
	}
	link := s.cfg.BaseURL + "/reset-password?token=" + token
	textBody, htmlBody, rerr := s.renderEmail("reset_link", map[string]interface{}{"Link": link})
	if rerr != nil {
		slog.Error("admin send-reset email render failed", "err", rerr)
		http.Redirect(w, r, "/admin/tenants/"+slug+"/users/"+uid.String()+"/edit?error=render+failed", http.StatusFound)
		return
	}
	if serr := s.mailer.SendMIME(u.Email, "Your thesada password reset link", textBody, htmlBody); serr != nil {
		slog.Error("admin send-reset email send failed", "user_id", uid, "email", u.Email, "err", serr)
		http.Redirect(w, r, "/admin/tenants/"+slug+"/users/"+uid.String()+"/edit?error=smtp+failed", http.StatusFound)
		return
	}
	slog.Info("admin send-reset ok", "user_id", uid, "email", u.Email)
	http.Redirect(w, r, "/admin/tenants/"+slug+"/users/"+uid.String()+"/edit?ok=reset+sent", http.StatusFound)
}

// ---------------------------------------------------------------------------
// Device reassignment
// ---------------------------------------------------------------------------

// handleAdminDevices lists every device across every tenant with a
// tenant-reassign dropdown. Super-admin only.
// in: writer, request. out: HTML page.
func (s *Server) handleAdminDevices(w http.ResponseWriter, r *http.Request) {
	devices, err := s.services.Devices.ListAllForAdmin(r.Context())
	if err != nil {
		slog.Error("admin device list failed", "err", err)
		http.Error(w, "device list failed", http.StatusInternalServerError)
		return
	}
	tenants, err := s.services.Tenants.List()
	if err != nil {
		slog.Error("admin tenant list failed", "err", err)
		http.Error(w, "tenant list failed", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "admin-devices.html", map[string]interface{}{
		"Devices": devices,
		"Tenants": tenants,
	})
}

// handleAdminDeviceReassign moves a device to a different tenant. The
// on-device mqtt.topic_prefix still needs to be updated out-of-band - this
// handler only touches the app-side row.
// in: writer, POST to /admin/devices/{id}/reassign with target_tenant form field.
func (s *Server) handleAdminDeviceReassign(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	target := r.PostFormValue("target_tenant")
	if !s.services.Tenants.ExistsBySlug(target) {
		http.Redirect(w, r, "/admin/devices?error=unknown+tenant", http.StatusFound)
		return
	}
	if err := s.services.Devices.Reassign(r.Context(), id, target); err != nil {
		slog.Error("admin device reassign failed", "device", id, "target", target, "err", err)
		http.Redirect(w, r, "/admin/devices?error=reassign+failed+(duplicate+device_id+in+target?)", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/devices?ok=reassigned", http.StatusFound)
}

