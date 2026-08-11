// Super-admin write-only tenant-secret-defaults UI. Same contract as the
// per-device page: the operator sets and overwrites values, the page shows
// set/unset only, and no handler here ever reads a value back -
// SecretService.RevealTenantSecret and Resolve stay server-side, used by the
// fan-out below and by provisioning. All handlers assume the
// authmw.RequireSuperAdmin wrap.
//
// A default is the value every device in the tenant resolves to unless it has
// its own override, so rotation is one write here plus a fan-out, rather than
// one write per device.
package web

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/authz"
	"thesada.app/app/pkg/service"
)

// tenantSecretField is one row of the tenant defaults form: the storage field,
// whether a default is stored, and how many paired devices currently inherit
// it. The value is never carried.
type tenantSecretField struct {
	Field     string
	Set       bool
	Inheritor int
}

// tenantSecretFields is the ordered field list for the tenant page: the
// scalars, then whatever WiFi rows already exist. No per-SSID expansion - a
// tenant default is not tied to any one device's network list, so there is no
// config to expand from.
// in: stored status map. out: ordered storage fields.
func tenantSecretFields(status map[string]bool) []string {
	return secretDisplayFields(status, nil)
}

// handleAdminTenantSecrets renders the write-only defaults page for a tenant.
// in: writer, GET /admin/tenants/{slug}/secrets. out: HTML page.
func (s *Server) handleAdminTenantSecrets(w http.ResponseWriter, r *http.Request) {
	tenant, _, ok := s.tenantSecretTarget(w, r)
	if !ok {
		return
	}

	status, err := s.services.Secrets.TenantStatus(r.Context(), tenant.ID)
	if err != nil {
		slog.Error("tenant secrets status failed", "tenant", tenant.ID, "err", err)
		http.Error(w, "status error", http.StatusInternalServerError)
		return
	}
	displayFields := tenantSecretFields(status)

	// One query for every count. A failure here costs the counts, not the page:
	// the operator still needs the form and the Clear buttons to recover.
	counts, err := s.services.Secrets.ProvisionTargetCounts(r.Context(), tenant.ID)
	countsKnown := err == nil
	if err != nil {
		slog.Error("tenant secret target counts failed", "tenant", tenant.ID, "err", err)
	}

	fields := make([]tenantSecretField, 0, len(displayFields))
	for _, f := range displayFields {
		fields = append(fields, tenantSecretField{
			Field: f, Set: status[f], Inheritor: counts[f],
		})
	}

	s.render(w, r, "admin-tenant-secrets.html", map[string]interface{}{
		"Tenant":      tenant,
		"Enabled":     s.services.Secrets.Enabled(),
		"Fields":      fields,
		"CountsKnown": countsKnown,
		"Ok":          r.URL.Query().Get("ok"),
		"Error":       r.URL.Query().Get("error"),
	})
}

// handleAdminTenantSecretsSet stores or overwrites one tenant default, then
// PRG-redirects. Storing is all this does - devices keep their old NVS value
// until the operator runs the fan-out, and the redirect says so, because a
// rotation that silently half-applied would be worse than one that did not.
// in: writer, POST /admin/tenants/{slug}/secrets/set. out: 302 to page.
func (s *Server) handleAdminTenantSecretsSet(w http.ResponseWriter, r *http.Request) {
	tenant, dest, ok := s.tenantSecretTarget(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	field := r.PostFormValue("field")
	value := r.PostFormValue("value")
	if field == "" || value == "" {
		http.Redirect(w, r, dest+"?error=field+and+value+required", http.StatusFound)
		return
	}

	if err := s.services.Secrets.SetTenantSecret(r.Context(), tenant.ID, field, value); err != nil {
		slog.Warn("set tenant secret failed", "tenant", tenant.ID, "field", field, "err", err)
		http.Redirect(w, r, dest+"?error=set+failed", http.StatusFound)
		return
	}

	targets, terr := s.services.Secrets.ProvisionTargets(r.Context(), tenant.ID, field)
	countKnown := terr == nil
	if terr != nil {
		// The write landed; only the count is unknown. Reporting 0 here would
		// read as "nothing to provision", the exact opposite of the truth.
		slog.Error("tenant secret targets failed", "tenant", tenant.ID, "field", field, "err", terr)
	}

	user := authmw.CurrentUser(r)
	actor := ""
	if user != nil {
		actor = user.Email
	}
	detail := map[string]any{"field": field}
	if countKnown {
		detail["inheritors"] = len(targets)
	}
	slog.Info("tenant_secret.state_change", "action", "set",
		"tenant", tenant.ID, "field", field,
		"inheritors", len(targets), "inheritors_known", countKnown, "actor", actor)
	s.audit(r.Context(), user, authz.TenantSecretSet, service.AuditEntry{
		TargetType: "tenant", TargetID: tenant.ID, TenantID: tenant.ID,
		Detail: detail,
	})

	if !countKnown {
		http.Redirect(w, r,
			dest+"?ok=default+set+"+url.QueryEscape(field)+
				"&error=inheritor+count+unavailable+-+run+Push+to+devices",
			http.StatusFound)
		return
	}
	http.Redirect(w, r,
		dest+"?ok=default+set+"+url.QueryEscape(field)+"+("+itoa(len(targets))+"+devices+need+provisioning)",
		http.StatusFound)
}

// handleAdminTenantSecretsSetWifi stores a per-SSID WiFi default. The field is
// built server-side from the SSID (service.WifiSecretField), so the operator
// names a network rather than typing a storage key - the page has no other way
// to create a WiFi default, since a tenant has no device config to expand SSIDs
// from and the bare legacy key is rejected.
// in: writer, POST /admin/tenants/{slug}/secrets/set-wifi. out: 302 to page.
func (s *Server) handleAdminTenantSecretsSetWifi(w http.ResponseWriter, r *http.Request) {
	tenant, dest, ok := s.tenantSecretTarget(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	ssid := strings.TrimSpace(r.PostFormValue("ssid"))
	value := r.PostFormValue("value")
	if ssid == "" || value == "" {
		http.Redirect(w, r, dest+"?error=ssid+and+password+required", http.StatusFound)
		return
	}
	field := service.WifiSecretField(ssid)

	if err := s.services.Secrets.SetTenantSecret(r.Context(), tenant.ID, field, value); err != nil {
		slog.Warn("set tenant wifi secret failed", "tenant", tenant.ID, "ssid", ssid, "err", err)
		http.Redirect(w, r, dest+"?error=set+failed", http.StatusFound)
		return
	}

	user := authmw.CurrentUser(r)
	actor := ""
	if user != nil {
		actor = user.Email
	}
	slog.Info("tenant_secret.state_change", "action", "set",
		"tenant", tenant.ID, "field", field, "actor", actor)
	s.audit(r.Context(), user, authz.TenantSecretSet, service.AuditEntry{
		TargetType: "tenant", TargetID: tenant.ID, TenantID: tenant.ID,
		Detail: map[string]any{"field": field},
	})

	http.Redirect(w, r, dest+"?ok=default+set+"+url.QueryEscape(field), http.StatusFound)
}

// handleAdminTenantSecretsClear deletes a tenant default. Devices with an
// override are unaffected; devices that were inheriting resolve to nothing
// afterwards and keep whatever is already in their NVS.
// in: writer, POST /admin/tenants/{slug}/secrets/clear. out: 302 to page.
func (s *Server) handleAdminTenantSecretsClear(w http.ResponseWriter, r *http.Request) {
	tenant, dest, ok := s.tenantSecretTarget(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	field := r.PostFormValue("field")
	if field == "" {
		http.Redirect(w, r, dest+"?error=field+required", http.StatusFound)
		return
	}

	deleted, err := s.services.Secrets.ClearTenantSecret(r.Context(), tenant.ID, field)
	if err != nil {
		slog.Warn("clear tenant secret failed", "tenant", tenant.ID, "field", field, "err", err)
		http.Redirect(w, r, dest+"?error=clear+failed", http.StatusFound)
		return
	}
	if !deleted {
		http.Redirect(w, r, dest+"?error=no+default+to+clear", http.StatusFound)
		return
	}

	user := authmw.CurrentUser(r)
	actor := ""
	if user != nil {
		actor = user.Email
	}
	slog.Info("tenant_secret.state_change", "action", "clear",
		"tenant", tenant.ID, "field", field, "actor", actor)
	s.audit(r.Context(), user, authz.TenantSecretClear, service.AuditEntry{
		TargetType: "tenant", TargetID: tenant.ID, TenantID: tenant.ID,
		Detail: map[string]any{"field": field},
	})

	http.Redirect(w, r, dest+"?ok=default+cleared+(device+NVS+unchanged)", http.StatusFound)
}

// handleAdminTenantSecretsProvision is the rotation fan-out: push the tenant
// default for one field to every paired device that does not override it.
//
// Synchronous and best-effort by design. There is no job queue in this app, and
// inventing a durable one for this would be a bigger feature than the fan-out
// itself; a device that is offline is reported as unreachable and stays on its
// old value until the next run or the next pair, both of which provision from
// the store. What this must never do is silently skip devices, so every device
// is counted and the counts land in the audit entry.
// in: writer, POST /admin/tenants/{slug}/secrets/provision. out: 302 to page.
func (s *Server) handleAdminTenantSecretsProvision(w http.ResponseWriter, r *http.Request) {
	tenant, dest, ok := s.tenantSecretTarget(w, r)
	if !ok {
		return
	}
	if !s.services.Secrets.Enabled() {
		http.Redirect(w, r, dest+"?error=secrets+disabled", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	field := r.PostFormValue("field")
	if field == "" {
		http.Redirect(w, r, dest+"?error=field+required", http.StatusFound)
		return
	}

	value, found, err := s.services.Secrets.RevealTenantSecret(r.Context(), tenant.ID, field)
	if err != nil {
		slog.Error("reveal tenant secret failed", "tenant", tenant.ID, "field", field, "err", err)
		http.Redirect(w, r, dest+"?error=decrypt+failed", http.StatusFound)
		return
	}
	if !found {
		http.Redirect(w, r, dest+"?error=no+default+set", http.StatusFound)
		return
	}

	targets, err := s.services.Secrets.ProvisionTargets(r.Context(), tenant.ID, field)
	if err != nil {
		slog.Error("tenant secret targets failed", "tenant", tenant.ID, "field", field, "err", err)
		http.Redirect(w, r, dest+"?error=target+lookup+failed", http.StatusFound)
		return
	}

	// Detached from the request: a fleet sweep that dies because the operator
	// hit reload would leave the fleet split with no audit record of which half
	// moved. The budget is per device so a large tenant is not cut short, and
	// pushSecret carries its own 10s per-device timeout underneath.
	fanCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()),
		time.Duration(len(targets)+1)*fanOutPerDeviceBudget)
	defer cancel()

	out := s.fanOutTenantSecret(fanCtx, tenant.ID, field, value, targets)

	user := authmw.CurrentUser(r)
	actor := ""
	if user != nil {
		actor = user.Email
	}
	slog.Info("tenant_secret.state_change", "action", "provision",
		"tenant", tenant.ID, "field", field, "targets", len(targets),
		"pushed", out.Pushed, "unreachable", out.Unreachable,
		"rejected", out.Rejected, "skipped", out.Skipped, "actor", actor)
	// Its own budget, not the sweep's leftovers: a truncated sweep is exactly
	// when the audit row matters, and fanCtx is spent by then.
	auditCtx, acancel := context.WithTimeout(context.WithoutCancel(r.Context()), 5*time.Second)
	defer acancel()
	s.audit(auditCtx, user, authz.TenantSecretProvision, service.AuditEntry{
		TargetType: "tenant", TargetID: tenant.ID, TenantID: tenant.ID,
		Detail: map[string]any{
			"field": field, "targets": len(targets), "pushed": out.Pushed,
			"unreachable": out.Unreachable, "rejected": out.Rejected, "skipped": out.Skipped,
		},
	})

	msg := "pushed+" + itoa(out.Pushed) + "+of+" + itoa(len(targets))
	if out.Unreachable > 0 {
		msg += "+(" + itoa(out.Unreachable) + "+unreachable)"
	}
	if out.Rejected > 0 {
		msg += "+(" + itoa(out.Rejected) + "+rejected)"
	}
	if out.Skipped > 0 {
		msg += "+(" + itoa(out.Skipped) + "+skipped)"
	}
	http.Redirect(w, r, dest+"?ok="+msg, http.StatusFound)
}

// fanOutPerDeviceBudget bounds the whole sweep at this much per target, on top
// of pushSecret's own 10s per-device timeout. A sweep that runs past it stops
// and reports what it managed, rather than running unbounded in the background.
const fanOutPerDeviceBudget = 15 * time.Second

// fanOutResult counts what a sweep did. Every target lands in exactly one
// bucket, and the four sum to len(targets), so a silently dropped device is
// impossible to hide.
type fanOutResult struct {
	Pushed      int
	Unreachable int // no response from the device
	Rejected    int // device answered and refused the write
	Skipped     int // never attempted (lookup failed, or budget exhausted)
}

// fanOutTenantSecret pushes one value to each target device over MQTT. A
// device that cannot be reached is counted, not fatal: aborting the sweep on
// the first offline device would leave the fleet split with no way to tell
// which half moved. A device that ANSWERS and refuses is counted separately -
// it is a broken device, not an absent one, and only the log distinguishes
// them afterwards.
//
// Takes a ctx rather than the request: the caller detaches it so an operator
// closing the tab cannot abort a half-finished rotation.
// in: ctx, tenant, storage field, plaintext, device pks. out: counts.
func (s *Server) fanOutTenantSecret(ctx context.Context, tenantID, field, value string, targets []uuid.UUID) fanOutResult {
	var out fanOutResult
	// The tenant default is never the legacy bare key (SetTenantSecret rejects
	// it), so the firmware field is the storage field and no per-device SSID
	// lookup is needed.
	for i, pk := range targets {
		if ctx.Err() != nil {
			slog.Error("tenant_secret.fanout_truncated", "tenant", tenantID, "field", field,
				"done", i, "targets", len(targets), "err", ctx.Err())
			out.Skipped += len(targets) - i
			return out
		}
		device, err := s.services.Devices.GetByIDAny(ctx, pk)
		if err != nil || device == nil {
			slog.Error("tenant_secret.fanout_lookup_failed", "tenant", tenantID, "device", pk, "err", err)
			out.Skipped++
			continue
		}
		msg, ok := s.pushSecret(ctx, s.deviceTopicPrefix(device), field, value)
		if !ok {
			// msg is a fixed, value-free string built by pushSecret.
			slog.Warn("tenant_secret.fanout_push_failed", "tenant", tenantID,
				"device", device.DeviceID, "field", field, "reason", msg)
			if strings.Contains(msg, "rejected") {
				out.Rejected++
			} else {
				out.Unreachable++
			}
			continue
		}
		out.Pushed++
	}
	return out
}

// tenantSecretTarget resolves {slug} to a tenant and the page URL to redirect
// back to, writing the 404/500 itself when it cannot. Shared by every handler
// in this file so each one starts with the same three lines instead of the
// same twenty.
// in: writer, request. out: tenant, redirect dest, ok.
func (s *Server) tenantSecretTarget(w http.ResponseWriter, r *http.Request) (*service.Tenant, string, bool) {
	slug := r.PathValue("slug")
	tenant, err := s.services.Tenants.Get(slug)
	// Get signals a missing tenant with ErrNotFound, never (nil, nil): a typo'd
	// slug is a 404, and only a real backend failure is a 500 (AGENTS.md: a
	// backend error must not masquerade as 404, nor a 404 as an error).
	if errors.Is(err, service.ErrNotFound) {
		http.NotFound(w, r)
		return nil, "", false
	}
	if err != nil {
		slog.Error("tenant lookup failed", "tenant", slug, "err", err)
		http.Error(w, "tenant lookup failed", http.StatusInternalServerError)
		return nil, "", false
	}
	return tenant, "/admin/tenants/" + url.PathEscape(slug) + "/secrets", true
}
