package web

import (
	"fmt"
	"html/template"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"
)

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
	"freshnessBadge":   freshnessBadge,
	"sortUnix":         sortUnix,
	"sortUnixTime":     sortUnixTime,
	"sortInt64":        sortInt64,
	"sortUptime":       sortUptime,
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
	if rv.Kind() == reflect.Pointer {
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
		return " °"
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

// A device is live while MQTT has been seen inside this window. send_interval_s
// defaults to 0, so a running node is chatty and five quiet minutes is late.
const freshnessLive = 5 * time.Minute

// After this, last_seen is offline. An uptime sample older than this is
// marked old. That mark is about the number, not whether the device is offline.
const freshnessOffline = 15 * time.Minute

// freshnessState classifies last_seen_at. A nil or zero time is unknown.
// A future timestamp is live. in: last seen, now. out: label, tailwind classes.
func freshnessState(at *time.Time, now time.Time) (string, string) {
	if at == nil || at.IsZero() {
		return "unknown", "bg-slate-100 text-slate-600"
	}
	age := now.Sub(*at)
	if age < 0 {
		age = 0
	}
	switch {
	case age <= freshnessLive:
		return "live", "bg-emerald-100 text-emerald-800"
	case age <= freshnessOffline:
		return "stale", "bg-amber-100 text-amber-800"
	default:
		return "offline", "bg-rose-100 text-rose-800"
	}
}

// freshnessBadge renders the state span. data-freshness is the seen instant
// so an open page can age it: a quiet device emits no MQTT event.
// in: last seen. out: a span.
func freshnessBadge(at *time.Time) template.HTML {
	label, class := freshnessState(at, time.Now())
	seen := "unknown"
	if at != nil && !at.IsZero() {
		seen = at.UTC().Format(time.RFC3339)
	}
	live := strconv.FormatInt(freshnessLive.Milliseconds(), 10)
	off := strconv.FormatInt(freshnessOffline.Milliseconds(), 10)
	return template.HTML(`<span class="text-xs px-1.5 py-0.5 rounded ` + class +
		`" data-freshness="` + seen +
		`" data-live-ms="` + live +
		`" data-offline-ms="` + off + `">` + label + `</span>`)
}

// uptimeLive renders a human-readable "live" uptime from the last reported
// uptime sample plus wall-clock elapsed since the sample arrived. Returns
// "-" if either input is nil. Appends "(old)" when the sample is past
// freshnessOffline. The number is extrapolated. The device may still be live.
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
	if time.Duration(elapsed)*time.Second > freshnessOffline {
		s += " (old)"
	}
	return s
}

// sortUnix is the numeric sort key for a nullable timestamp.
// in: *time.Time. out: unix seconds, or empty when unset.
func sortUnix(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return strconv.FormatInt(t.Unix(), 10)
}

// sortUnixTime is sortUnix for a value timestamp.
// in: time.Time. out: unix seconds, or empty when zero.
func sortUnixTime(t time.Time) string {
	return sortUnix(&t)
}

// sortInt64 is the numeric sort key for a nullable sample.
// in: *int64. out: decimal text, or empty when unset.
func sortInt64(v *int64) string {
	if v == nil {
		return ""
	}
	return strconv.FormatInt(*v, 10)
}

// sortUptime matches the live uptime total so the column sorts as it reads.
// in: last uptime seconds, time that sample was received. out: decimal seconds.
func sortUptime(secs *int64, at *time.Time) string {
	if secs == nil || at == nil {
		return ""
	}
	total := *secs + int64(time.Since(*at).Seconds())
	if total < 0 {
		total = 0
	}
	return strconv.FormatInt(total, 10)
}
