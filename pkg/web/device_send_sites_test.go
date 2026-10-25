package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// deviceSendSites is every function in this package that talks to the broker
// (an <x>.mqtt.<Method> call), with the admin_audit action that records it or
// why it needs none. TestDeviceSendSitesAreAudited forces that decision for a
// new site; it does not prove the row is written. That is checked by
// TestAdminAuditTrail, TestAdminMqttShell and the service audit tests.
var deviceSendSites = map[string]string{
	"runCLICmd":                  "device.command, written at enqueue in handleAdminDeviceConfigCmd",
	"runCLIWrite":                "device.config_write, written at enqueue in handleAdminDeviceConfigWrite",
	"handleAdminMqttWS":          "mqtt.shell_publish / mqtt.shell_subscribe, one row per session",
	"handleAdminDeviceDelete":    "device.delete",
	"cascadeDeleteOne":           "device.delete (bulk)",
	"preemptiveCertClear":        "step of device.delete / cert.revoke",
	"bulkOTACheck":               "ota.dispatch",
	"handleAdminDevicePairIssue": "cert.issue",
	"pushCertPart":               "step of cert.issue",
	"runCLI":                     "step of cert.issue",
	"pushSecret":                 "device_secret.provision / tenant_secret.provision / step of cert.issue",
	"provisionDeviceDynsec":      "broker ACL, step of cert.issue or a claim (device_enrollments row)",
	"teardownDeviceDynsec":       "broker ACL, step of cert.revoke / device.delete",
	"ownerCertClear":             "cert.revoke",
	"deviceSecretState":          "read only (secret.info presence)",
	"recoveryPath":               "read only (dynsec client state)",
}

func TestDeviceSendSitesAreAudited(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				c, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
					if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "mqtt" {
						found[fd.Name.Name] = true
					}
				}
				return true
			})
		}
	}
	if len(found) == 0 {
		t.Fatal("no broker calls found; the parser no longer matches the code")
	}
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if _, ok := deviceSendSites[n]; !ok {
			t.Errorf("%s talks to the broker but is not in deviceSendSites: audit it, then list it", n)
		}
	}
	for n := range deviceSendSites {
		if !found[n] {
			t.Errorf("deviceSendSites lists %s, which no longer talks to the broker", n)
		}
	}
}
