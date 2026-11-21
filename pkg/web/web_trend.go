package web

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"thesada.app/app/pkg/authmw"
	"thesada.app/app/pkg/authz"
	"thesada.app/app/pkg/service"
)

// canEditTrendRule applies the Lua rules check: canEditRules for a device rule, an
// operator or a tenant admin for a tenant-wide one. nil device means tenant-wide.
func canEditTrendRule(me *service.User, tenantID string, d *service.Device) bool {
	if d != nil {
		return canEditRules(me, d)
	}
	return me != nil && (authz.Can(me, authz.RulesTenantPush) || (me.IsAdmin && me.TenantID == tenantID))
}

// errTrendForbidden: the caller may not change this rule.
var errTrendForbidden = errors.New("forbidden")

// authorizeTrendRule checks the caller may change an existing rule.
// in: request, tenant, rule id. out: nil, errTrendForbidden, ErrTrendRuleNotFound or a lookup error.
func (s *Server) authorizeTrendRule(r *http.Request, tenantID string, id uuid.UUID) error {
	pk, err := s.services.Alerts.TrendRuleDevice(r.Context(), tenantID, id)
	if err != nil {
		return err
	}
	d, found, err := s.trendRuleDevice(tenantID, pk)
	if err != nil {
		return err
	}
	if !found || !canEditTrendRule(authmw.CurrentUser(r), tenantID, d) {
		return errTrendForbidden
	}
	return nil
}

// trendRuleDevice loads the device a rule targets, nil for a tenant-wide rule.
// in: tenant, device pk or nil. out: device, found, error.
func (s *Server) trendRuleDevice(tenantID string, pk *uuid.UUID) (*service.Device, bool, error) {
	if pk == nil {
		return nil, true, nil
	}
	d, err := s.services.Devices.GetByID(*pk, tenantID)
	if err != nil {
		return nil, false, err
	}
	return d, d != nil, nil
}

// trendUnitSeconds maps the window unit picker to seconds.
var trendUnitSeconds = map[string]int{"min": 60, "h": 3600}

// handleTrendRuleAdd stores one trend rule for the tenant.
// in: writer, POST form (metric, direction, delta, window, unit, severity, device). out: redirect or 400.
func (s *Server) handleTrendRuleAdd(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	tenantID := authmw.EffectiveTenantID(r)
	delta, err := strconv.ParseFloat(strings.TrimSpace(r.PostFormValue("delta")), 64)
	if err != nil {
		http.Error(w, "change must be a number", http.StatusBadRequest)
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(r.PostFormValue("window")))
	unit, okUnit := trendUnitSeconds[r.PostFormValue("unit")]
	if err != nil || !okUnit || n <= 0 || n > service.TrendWindowMax/unit {
		http.Error(w, "window must be between 1 minute and 7 days", http.StatusBadRequest)
		return
	}
	rule := service.TrendRule{
		Metric:    strings.TrimSpace(r.PostFormValue("metric")),
		Direction: r.PostFormValue("direction"),
		Delta:     delta,
		WindowS:   n * unit,
		Severity:  r.PostFormValue("severity"),
	}
	if dev := r.PostFormValue("device"); dev != "" {
		pk, err := uuid.Parse(dev)
		if err != nil {
			http.Error(w, "invalid device", http.StatusBadRequest)
			return
		}
		rule.DevicePK = &pk
	}
	d, found, err := s.trendRuleDevice(tenantID, rule.DevicePK)
	if err != nil {
		slog.Error("alerts.trend_save_failed", "part", "device", "tenant", tenantID, "err", err)
		http.Redirect(w, r, "/alerts?err=rules#rules", http.StatusSeeOther)
		return
	}
	if !found {
		http.Error(w, "device not found", http.StatusBadRequest)
		return
	}
	if !canEditTrendRule(authmw.CurrentUser(r), tenantID, d) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	_, err = s.services.Alerts.CreateTrendRule(r.Context(), tenantID, rule)
	switch {
	case errors.Is(err, service.ErrTrendRuleInvalid):
		http.Error(w, strings.TrimPrefix(err.Error(), service.ErrTrendRuleInvalid.Error()+": "), http.StatusBadRequest)
	case errors.Is(err, service.ErrTrendDevice):
		http.Error(w, "device not found", http.StatusBadRequest)
	case errors.Is(err, service.ErrQuotaTrendRules):
		http.Error(w, strings.TrimPrefix(err.Error(), service.ErrQuotaTrendRules.Error()+": "), http.StatusBadRequest)
	case err != nil:
		slog.Error("alerts.trend_save_failed", "part", "add", "tenant", tenantID, "err", err)
		http.Redirect(w, r, "/alerts?err=rules#rules", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/alerts?saved=rules#rules", http.StatusSeeOther)
	}
}

// handleTrendRuleToggle switches one rule on or off.
// in: writer, POST form (enabled), path id. out: redirect or error.
func (s *Server) handleTrendRuleToggle(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	s.trendRuleChange(w, r, func(tenantID string, id uuid.UUID) error {
		return s.services.Alerts.SetTrendRuleEnabled(r.Context(), tenantID, id, formChecked(r, "enabled"))
	})
}

// handleTrendRuleDelete removes one rule.
// in: writer, POST, path id. out: redirect or error.
func (s *Server) handleTrendRuleDelete(w http.ResponseWriter, r *http.Request) {
	s.trendRuleChange(w, r, func(tenantID string, id uuid.UUID) error {
		return s.services.Alerts.DeleteTrendRule(r.Context(), tenantID, id)
	})
}

// trendRuleChange parses the rule id and maps the service errors to replies.
// in: writer, request, change. out: redirect or error.
func (s *Server) trendRuleChange(w http.ResponseWriter, r *http.Request, change func(string, uuid.UUID) error) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid rule", http.StatusBadRequest)
		return
	}
	tenantID := authmw.EffectiveTenantID(r)
	err = s.authorizeTrendRule(r, tenantID, id)
	if err == nil {
		err = change(tenantID, id)
	}
	switch {
	case errors.Is(err, errTrendForbidden):
		http.Error(w, "forbidden", http.StatusForbidden)
	case errors.Is(err, service.ErrTrendRuleNotFound):
		http.Error(w, "rule not found", http.StatusNotFound)
	case err != nil:
		slog.Error("alerts.trend_save_failed", "part", "change", "tenant", tenantID, "rule", id, "err", err)
		http.Redirect(w, r, "/alerts?err=rules#rules", http.StatusSeeOther)
	default:
		http.Redirect(w, r, "/alerts?saved=rules#rules", http.StatusSeeOther)
	}
}
