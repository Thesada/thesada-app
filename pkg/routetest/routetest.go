// Package routetest checks that every HTTP route a package registers is
// classified (public, user, admin) and wrapped by the matching authmw gate.
// Test-only helper, same role as servicetest and mqtttest.
package routetest

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Class is who may reach a route, and so which authmw wrapper it needs.
type Class int

const (
	Public Class = iota // no wrapper
	User                // authmw.RequireAuth or RequireAuthJSON
	Admin               // authmw.RequireSuperAdmin or RequireSuperAdminJSON
)

var wrapper = map[Class]string{Public: "", User: "RequireAuth", Admin: "RequireSuperAdmin"}

// Registered parses every non-test Go file in dir and returns pattern ->
// authmw wrapper name ("" when the handler is not wrapped). Whole package,
// so a route registered outside the routes file is still seen.
// in: t, package dir. out: map.
func Registered(t *testing.T, dir string) map[string]string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		collect(t, path, f, out)
	}
	if len(out) == 0 {
		t.Fatalf("%s: no routes found; the parser no longer matches the routes func", dir)
	}
	return out
}

// collect adds the routes one parsed file registers to out.
// in: t, file path, parsed file, map. out: none.
func collect(t *testing.T, path string, f *ast.File, out map[string]string) {
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || len(c.Args) != 2 {
			return true
		}
		sel, ok := c.Fun.(*ast.SelectorExpr)
		if !ok || (sel.Sel.Name != "HandleFunc" && sel.Sel.Name != "Handle") {
			return true
		}
		lit, ok := c.Args[0].(*ast.BasicLit)
		if !ok {
			t.Errorf("%s: route pattern is not a string literal", path)
			return true
		}
		pattern, _ := strconv.Unquote(lit.Value)
		w := ""
		if wc, ok := c.Args[1].(*ast.CallExpr); ok {
			if ws, ok := wc.Fun.(*ast.SelectorExpr); ok {
				if x, ok := ws.X.(*ast.Ident); ok && x.Name == "authmw" {
					w = ws.Sel.Name
				}
			}
		}
		if _, dup := out[pattern]; dup {
			t.Errorf("%s: %q registered twice", path, pattern)
		}
		out[pattern] = w
		return true
	})
}

// Check compares the registered routes with the class table: no unclassified
// route, no stale entry, the wrapper matches the class, and every user route
// with a path parameter is in cross (the routes with a cross-tenant case).
// in: t, registered, table, cross-tenant list. out: none.
func Check(t *testing.T, got map[string]string, table map[string]Class, cross []string) {
	t.Helper()
	inCross := map[string]bool{}
	for _, r := range cross {
		inCross[r] = true
		if c, ok := table[r]; !ok || c != User {
			t.Errorf("cross-tenant route %q is not a classified user route", r)
		}
	}
	patterns := make([]string, 0, len(got))
	for p := range got {
		patterns = append(patterns, p)
	}
	sort.Strings(patterns)
	for _, p := range patterns {
		class, ok := table[p]
		if !ok {
			t.Errorf("route %q is not classified: add it to the route table", p)
			continue
		}
		if want := wrapper[class]; got[p] != want && (want == "" || got[p] != want+"JSON") {
			t.Errorf("route %q: wrapper %q, want %q for its class", p, got[p], want)
		}
		if class == User && strings.Contains(p, "{") && !inCross[p] {
			t.Errorf("user route %q takes a path id but has no cross-tenant case", p)
		}
	}
	for p := range table {
		if _, ok := got[p]; !ok {
			t.Errorf("route table lists %q, which is no longer registered", p)
		}
	}
}
