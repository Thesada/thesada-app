package migrations

import (
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// rlsDataStepAllowed lists migrations whose unguarded data step is history.
// An entry that no longer matches a violation fails the test.
var rlsDataStepAllowed = map[string]string{
	"0025_alert_delivery_retry.sql":   "delivery_status backfill without the role switch. Applied history, alerts since then were dispatched, not rerun",
	"0031_cert_serial_tombstones.sql": "pubkey_hex backfill matched no rows under FORCE RLS. Rerun as the BYPASSRLS role by 0041",
}

var (
	sqlLineComment = regexp.MustCompile(`--[^\n]*`)
	sqlFuncBody    = regexp.MustCompile(`(?is)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\b.*?(\$[a-z_]*\$).*?\$[a-z_]*\$`)
	sqlRLSEvent    = regexp.MustCompile(`(?is)` +
		`ALTER\s+TABLE\s+(?:ONLY\s+)?(\w+)\s+(NO\s+)?FORCE\s+ROW\s+LEVEL\s+SECURITY` +
		`|(SET\s+(?:LOCAL\s+)?ROLE\s+thesada_app_admin)` +
		`|(RESET\s+ROLE|SET\s+(?:LOCAL\s+)?ROLE\s+(?:NONE|DEFAULT))` +
		`|(?:^|;|\bBEGIN\b|\(|\bAS\s*\()\s*(UPDATE|INSERT\s+INTO|DELETE\s+FROM)\s+(?:ONLY\s+)?(\w+)`)
)

type rlsViolation struct {
	file, verb, table string
}

// unguardedRLSDataSteps returns every UPDATE/INSERT/DELETE on a FORCE RLS
// table that runs without SET ROLE thesada_app_admin. Files run in name order.
func unguardedRLSDataSteps(files map[string]string) []rlsViolation {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	forced := map[string]bool{}
	var out []rlsViolation
	for _, name := range names {
		body := sqlLineComment.ReplaceAllString(files[name], "")
		body = sqlFuncBody.ReplaceAllString(body, "")
		admin := false
		for _, m := range sqlRLSEvent.FindAllStringSubmatch(body, -1) {
			switch {
			case m[1] != "":
				forced[strings.ToLower(m[1])] = m[2] == ""
			case m[3] != "":
				admin = true
			case m[4] != "":
				admin = false
			case m[5] != "":
				table := strings.ToLower(m[6])
				if forced[table] && !admin {
					verb := strings.ToUpper(strings.Fields(m[5])[0])
					out = append(out, rlsViolation{file: name, verb: verb, table: table})
				}
			}
		}
	}
	return out
}

func TestUnguardedRLSDataSteps_Fires(t *testing.T) {
	files := map[string]string{
		"0001_a.sql": "CREATE TABLE t (x int);\nINSERT INTO t VALUES (1);\nALTER TABLE t FORCE  ROW LEVEL SECURITY;\n",
		"0002_b.sql": "-- UPDATE t SET x = 2;\nUPDATE t SET x = 3;\n",
		"0003_c.sql": "SET LOCAL ROLE thesada_app_admin;\nDELETE FROM t;\nRESET ROLE;\nUPDATE t SET x = 4;\n",
		"0004_d.sql": "CREATE FUNCTION f() RETURNS trigger AS $$ BEGIN UPDATE t SET x = 5; RETURN NEW; END $$ LANGUAGE plpgsql;\n",
	}
	got := unguardedRLSDataSteps(files)
	want := []rlsViolation{{"0002_b.sql", "UPDATE", "t"}, {"0003_c.sql", "UPDATE", "t"}}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

// Every data step on a FORCE RLS table runs as the BYPASSRLS role, or the
// owner-run migrate changes zero rows without an error.
func TestMigrations_RLSDataStepsSetRole(t *testing.T) {
	names, err := fs.Glob(FS, "*.sql")
	if err != nil || len(names) == 0 {
		t.Fatalf("glob migrations: %v (%d files)", err, len(names))
	}
	files := map[string]string{}
	for _, n := range names {
		b, err := FS.ReadFile(n)
		if err != nil {
			t.Fatalf("read %s: %v", n, err)
		}
		files[n] = string(b)
	}
	hit := map[string]bool{}
	for _, v := range unguardedRLSDataSteps(files) {
		hit[v.file] = true
		if _, ok := rlsDataStepAllowed[v.file]; !ok {
			t.Errorf("%s: %s %s runs under FORCE RLS without SET LOCAL ROLE thesada_app_admin", v.file, v.verb, v.table)
		}
	}
	for f := range rlsDataStepAllowed {
		if !hit[f] {
			t.Errorf("allow-list entry %s matches no unguarded data step, remove it", f)
		}
	}
}
