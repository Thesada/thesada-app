// Super-admin audit trail browser: GET /admin/audit renders admin_audit
// rows newest-first with filters for actor email, action, target, and
// date range. Read-only (filters travel as GET query params, no CSRF
// needed) and assumes the authmw.RequireSuperAdmin wrap.
package web

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"thesada.app/app/pkg/authz"
	"thesada.app/app/pkg/service"
)

// auditPageLimit is the default (and only) page size for /admin/audit.
const auditPageLimit = 50

// auditDetailInlineMax is the longest detail JSON rendered inline; longer
// payloads collapse behind a <details> disclosure so rows stay one line.
const auditDetailInlineMax = 80

// auditFilterForm carries the raw filter values back into the form inputs
// so a filtered page re-renders with its own criteria filled in.
type auditFilterForm struct {
	Actor      string
	Action     string
	TargetType string
	TargetID   string
	From       string // yyyy-mm-dd as typed
	To         string
}

// auditRow is the view-model for one trail row: the record plus its detail
// JSON pre-rendered compactly (inline when short, truncated + expandable
// when long).
type auditRow struct {
	Rec          service.AuditRecord
	Detail       string // full compact JSON
	DetailShort  string // truncated inline text
	DetailIsLong bool
}

// parseAuditQuery maps /admin/audit query params onto an AuditFilter plus
// the raw form echo and the requested offset. Pure so the mapping is
// unit-testable. Bad dates are ignored (no filter) rather than erroring -
// an operator mistyping a date should see data, not a 400. The To date is
// inclusive on the form, so it becomes the exclusive day-after bound.
// in: URL query values. out: filter (Limit unset - caller pages), form echo, offset.
func parseAuditQuery(q url.Values) (service.AuditFilter, auditFilterForm, int) {
	form := auditFilterForm{
		Actor:      q.Get("actor"),
		Action:     q.Get("action"),
		TargetType: q.Get("target_type"),
		TargetID:   q.Get("target_id"),
		From:       q.Get("from"),
		To:         q.Get("to"),
	}
	f := service.AuditFilter{
		ActorEmail: form.Actor,
		Action:     form.Action,
		TargetType: form.TargetType,
		TargetID:   form.TargetID,
	}
	if t, err := time.Parse("2006-01-02", form.From); err == nil {
		f.From = t
	}
	if t, err := time.Parse("2006-01-02", form.To); err == nil {
		f.To = t.AddDate(0, 0, 1)
	}
	offset, err := strconv.Atoi(q.Get("offset"))
	if err != nil || offset < 0 {
		offset = 0
	}
	f.Offset = offset
	return f, form, offset
}

// auditPageURL rebuilds the /admin/audit query string for a pager link,
// keeping the active filters and swapping only the offset (dropped at 0
// so the first page has a clean URL).
// in: form echo, target offset. out: relative URL.
func auditPageURL(form auditFilterForm, offset int) string {
	q := url.Values{}
	for k, v := range map[string]string{
		"actor": form.Actor, "action": form.Action,
		"target_type": form.TargetType, "target_id": form.TargetID,
		"from": form.From, "to": form.To,
	} {
		if v != "" {
			q.Set(k, v)
		}
	}
	if offset > 0 {
		q.Set("offset", strconv.Itoa(offset))
	}
	if enc := q.Encode(); enc != "" {
		return "/admin/audit?" + enc
	}
	return "/admin/audit"
}

// newAuditRow renders one record's detail for the table: compact JSON,
// inline when short, truncated with the full payload behind a disclosure
// when long. An empty object renders as "" so no-detail rows stay blank.
// in: audit record. out: view-model row.
func newAuditRow(rec service.AuditRecord) auditRow {
	row := auditRow{Rec: rec}
	detail := string(rec.Detail)
	if detail == "{}" || detail == "" {
		return row
	}
	// Compact defensively; stored jsonb round-trips compact already.
	var buf []byte
	if b, err := json.Marshal(rec.Detail); err == nil {
		buf = b
	} else {
		buf = rec.Detail
	}
	row.Detail = string(buf)
	row.DetailShort = row.Detail
	if len(row.Detail) > auditDetailInlineMax {
		row.DetailIsLong = true
		row.DetailShort = row.Detail[:auditDetailInlineMax] + "..."
	}
	return row
}

// handleAdminAudit renders the audit-trail search page. Fetches one row
// past the page size to know whether a next page exists without a count
// query.
// in: writer, GET /admin/audit (+filter query params). out: HTML page.
func (s *Server) handleAdminAudit(w http.ResponseWriter, r *http.Request) {
	filter, form, offset := parseAuditQuery(r.URL.Query())
	filter.Limit = auditPageLimit + 1

	recs, err := s.services.Audit.List(r.Context(), filter)
	if err != nil {
		slog.Error("admin audit list failed", "err", err)
		http.Error(w, "audit list failed", http.StatusInternalServerError)
		return
	}
	hasNext := len(recs) > auditPageLimit
	if hasNext {
		recs = recs[:auditPageLimit]
	}
	rows := make([]auditRow, 0, len(recs))
	for _, rec := range recs {
		rows = append(rows, newAuditRow(rec))
	}

	data := map[string]interface{}{
		"Rows":    rows,
		"Filter":  form,
		"Actions": authz.Actions(),
		"Offset":  offset,
	}
	if offset > 0 {
		prev := offset - auditPageLimit
		if prev < 0 {
			prev = 0
		}
		data["PrevURL"] = auditPageURL(form, prev)
	}
	if hasNext {
		data["NextURL"] = auditPageURL(form, offset+auditPageLimit)
	}
	s.render(w, r, "admin-audit.html", data)
}
