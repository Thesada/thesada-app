// Unit coverage for the /admin/audit filter plumbing: query-param ->
// AuditFilter mapping, pager URL rebuilding, and the detail JSON
// truncation. All pure helpers - the List round-trip itself is covered in
// the service integration suite.
package web

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"thesada.app/app/pkg/service"
)

func TestParseAuditQuery(t *testing.T) {
	t.Run("maps_all_params", func(t *testing.T) {
		f, form, offset := parseAuditQuery(url.Values{
			"actor":       {"op@a"},
			"action":      {"cert.issue"},
			"target_type": {"device"},
			"target_id":   {"abc"},
			"from":        {"2026-07-01"},
			"to":          {"2026-07-07"},
			"offset":      {"100"},
		})
		if f.ActorEmail != "op@a" || f.Action != "cert.issue" ||
			f.TargetType != "device" || f.TargetID != "abc" {
			t.Errorf("filter = %+v, want mapped fields", f)
		}
		if want := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC); !f.From.Equal(want) {
			t.Errorf("From = %v, want %v", f.From, want)
		}
		// To is inclusive on the form -> exclusive day-after bound.
		if want := time.Date(2026, 7, 8, 0, 0, 0, 0, time.UTC); !f.To.Equal(want) {
			t.Errorf("To = %v, want %v (day after the typed date)", f.To, want)
		}
		if offset != 100 || f.Offset != 100 {
			t.Errorf("offset = %d/%d, want 100", offset, f.Offset)
		}
		if form.From != "2026-07-01" || form.To != "2026-07-07" {
			t.Errorf("form echo = %+v, want raw dates preserved", form)
		}
	})

	t.Run("bad_dates_and_offset_ignored", func(t *testing.T) {
		f, _, offset := parseAuditQuery(url.Values{
			"from":   {"july 1st"},
			"to":     {"2026-13-99"},
			"offset": {"-3"},
		})
		if !f.From.IsZero() || !f.To.IsZero() {
			t.Errorf("bad dates parsed: From=%v To=%v, want zero", f.From, f.To)
		}
		if offset != 0 {
			t.Errorf("offset = %d, want 0", offset)
		}
	})
}

func TestAuditPageURL(t *testing.T) {
	form := auditFilterForm{Actor: "op@a", Action: "cert.issue", From: "2026-07-01"}
	got := auditPageURL(form, 50)
	u, err := url.Parse(got)
	if err != nil {
		t.Fatalf("parse %q: %v", got, err)
	}
	q := u.Query()
	if q.Get("actor") != "op@a" || q.Get("action") != "cert.issue" ||
		q.Get("from") != "2026-07-01" || q.Get("offset") != "50" {
		t.Errorf("page URL %q lost filter state", got)
	}
	if q.Get("target_type") != "" || q.Get("to") != "" {
		t.Errorf("page URL %q carries empty params", got)
	}
	// Offset 0 keeps the first-page URL clean.
	if got := auditPageURL(auditFilterForm{}, 0); got != "/admin/audit" {
		t.Errorf("empty filter page URL = %q, want /admin/audit", got)
	}
}

func TestNewAuditRow(t *testing.T) {
	t.Run("empty_detail_stays_blank", func(t *testing.T) {
		row := newAuditRow(service.AuditRecord{Detail: json.RawMessage(`{}`)})
		if row.Detail != "" || row.DetailShort != "" || row.DetailIsLong {
			t.Errorf("empty detail rendered as %+v, want blanks", row)
		}
	})

	t.Run("short_detail_inline", func(t *testing.T) {
		row := newAuditRow(service.AuditRecord{Detail: json.RawMessage(`{"a":1}`)})
		if row.Detail != `{"a":1}` || row.DetailIsLong {
			t.Errorf("short detail = %+v, want inline untruncated", row)
		}
	})

	t.Run("long_detail_truncated_with_full_copy", func(t *testing.T) {
		long := `{"key":"` + strings.Repeat("x", 200) + `"}`
		row := newAuditRow(service.AuditRecord{Detail: json.RawMessage(long)})
		if !row.DetailIsLong {
			t.Fatal("long detail not flagged")
		}
		if row.Detail != long {
			t.Errorf("full detail lost: %q", row.Detail)
		}
		if len(row.DetailShort) != auditDetailInlineMax+len("...") ||
			!strings.HasSuffix(row.DetailShort, "...") {
			t.Errorf("DetailShort = %q (len %d), want %d chars + ellipsis",
				row.DetailShort, len(row.DetailShort), auditDetailInlineMax)
		}
	})
}
