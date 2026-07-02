// Super-admin debug page: build metadata + redacted live config dump.
// Read-only by design - no mutation, no log tail, no pprof. Sanitizer
// below masks any leaf whose key matches a sensitive pattern
// (password/secret/token/key/passphrase/credential), recursively,
// before the value reaches the template.
package web

import (
	"net/http"
	"os"
	"reflect"
	"regexp"
	"runtime"
	"strings"
	"time"

	"thesada.app/app/pkg/buildinfo"
)

// sensitiveKeyRE matches struct field names / map keys that must be masked
// before being rendered. Anchored to the end so "Username" is not masked
// while "AuthToken" is. "kek" is listed alongside "key" because the
// device-config root key fields end in "KEK" (key-encryption-key), which
// "key$" does not match; every such field name must end in a matched token.
var sensitiveKeyRE = regexp.MustCompile(`(?i)(password|secret|token|key|kek|passphrase|credential)$`)

// dsnRE strips the password segment of a Postgres-style URL. Matches
// `://user:password@host` and replaces the password with `***`.
var dsnRE = regexp.MustCompile(`^([^:]+://[^:@]+:)[^@]+(@.*)$`)

// debugRow is a single key/value pair rendered on the debug page.
type debugRow struct {
	Key   string
	Value string
}

// handleAdminDebug renders /admin/debug: build info, process info, and a
// recursively redacted dump of the live *config.Config.
// in: writer, request. out: HTML page.
func (s *Server) handleAdminDebug(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	build := []debugRow{
		{"Version", buildinfo.Version},
		{"Commit", buildinfo.Commit},
		{"Build time", buildinfo.BuildTime},
		{"Go runtime", runtime.Version()},
		{"GOOS/GOARCH", runtime.GOOS + "/" + runtime.GOARCH},
	}

	proc := []debugRow{
		{"Hostname", hostname},
		{"PID", itoa(os.Getpid())},
		{"Started at", buildinfo.StartedAt().UTC().Format(time.RFC3339)},
		{"Uptime", buildinfo.Uptime().Truncate(time.Second).String()},
		{"Heap Alloc", humanBytes(ms.Alloc)},
		{"Heap Sys", humanBytes(ms.Sys)},
		{"NumGC", itoaUint32(ms.NumGC)},
		{"Goroutines", itoa(runtime.NumGoroutine())},
	}

	cfg := sanitizeConfig(s.cfg)

	s.render(w, r, "admin-debug.html", map[string]interface{}{
		"Build":   build,
		"Process": proc,
		"Config":  cfg,
	})
}

// sanitizeConfig walks an arbitrary value via reflect and returns an
// ordered slice of debugRow so the template renders in struct field order
// (map iteration order would be non-deterministic). Sensitive leaves are
// replaced with "***". Postgres-style URLs are replaced via dsnRE.
// in: any value, typically *config.Config. out: ordered key/value rows.
func sanitizeConfig(v any) []debugRow {
	rows := []debugRow{}
	walk(reflect.ValueOf(v), "", &rows)
	return rows
}

// walk recursively traverses v, accumulating sanitized rows. prefix is
// the dotted key path (empty at top level).
// in: reflect.Value, dotted prefix, output slice pointer. out: none (mutates).
func walk(v reflect.Value, prefix string, out *[]debugRow) {
	if !v.IsValid() {
		return
	}
	for v.Kind() == reflect.Ptr || v.Kind() == reflect.Interface {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Struct:
		t := v.Type()
		for i := 0; i < v.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			key := f.Name
			if prefix != "" {
				key = prefix + "." + key
			}
			walk(v.Field(i), key, out)
		}
	case reflect.Map:
		iter := v.MapRange()
		for iter.Next() {
			k := iter.Key()
			ks := ""
			if k.Kind() == reflect.String {
				ks = k.String()
			} else {
				ks = "?"
			}
			key := ks
			if prefix != "" {
				key = prefix + "." + ks
			}
			walk(iter.Value(), key, out)
		}
	default:
		*out = append(*out, debugRow{Key: prefix, Value: redactLeaf(prefix, v)})
	}
}

// redactLeaf returns the rendered value for a leaf, replacing it with
// "***" if the trailing segment of the dotted key matches the sensitive
// regex. Postgres DSNs have the password component masked.
// in: dotted key, leaf value. out: string suitable for template render.
func redactLeaf(key string, v reflect.Value) string {
	last := key
	if i := strings.LastIndex(key, "."); i >= 0 {
		last = key[i+1:]
	}
	if sensitiveKeyRE.MatchString(last) {
		if !v.IsValid() || v.IsZero() {
			return ""
		}
		return "***"
	}
	s := valueString(v)
	if strings.Contains(s, "://") && strings.Contains(s, "@") {
		if m := dsnRE.ReplaceAllString(s, "${1}***${2}"); m != s {
			return m
		}
	}
	return s
}

// valueString renders a reflect.Value as a string without crashing on
// unsupported kinds.
// in: reflect.Value. out: stringified value.
func valueString(v reflect.Value) string {
	if !v.IsValid() {
		return ""
	}
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Bool:
		if v.Bool() {
			return "true"
		}
		return "false"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return itoa64(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return itoaU64(v.Uint())
	case reflect.Float32, reflect.Float64:
		return ftoa(v.Float())
	default:
		return v.String()
	}
}

// itoa returns base-10 string of an int.
func itoa(i int) string { return itoa64(int64(i)) }

// itoaUint32 returns base-10 string of a uint32.
func itoaUint32(i uint32) string { return itoaU64(uint64(i)) }

// itoa64 returns base-10 string of an int64 without strconv import in hot
// path code paths above (kept local for clarity).
func itoa64(i int64) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// itoaU64 returns base-10 string of a uint64.
func itoaU64(i uint64) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}

// ftoa renders a float64 with 2 decimals.
func ftoa(f float64) string {
	// Quick-and-dirty; runtime.MemStats fields used here are integers, so
	// this only fires for hypothetical float config values.
	whole := int64(f)
	frac := int64((f - float64(whole)) * 100)
	if frac < 0 {
		frac = -frac
	}
	return itoa64(whole) + "." + itoa64(frac)
}

// humanBytes formats a byte count with KB/MB/GB suffixes.
// in: count. out: e.g. "12.4 MB".
func humanBytes(n uint64) string {
	const (
		kb = 1024
		mb = kb * 1024
		gb = mb * 1024
	)
	switch {
	case n >= gb:
		return ftoa(float64(n)/float64(gb)) + " GB"
	case n >= mb:
		return ftoa(float64(n)/float64(mb)) + " MB"
	case n >= kb:
		return ftoa(float64(n)/float64(kb)) + " KB"
	default:
		return itoaU64(n) + " B"
	}
}
