// Template registration audit. parseTemplates panics (template.Must) on a
// syntax error, so calling it here fails the suite the moment a template
// breaks - the server would refuse to boot with the same panic. The second
// test closes the other gap: a template file added on disk but never
// listed in parseTemplates would silently 500 at render time with
// "template not found".
package web

import (
	"bytes"
	"io/fs"
	"path"
	"strings"
	"testing"

	"thesada.app/app/pkg/service"
)

func TestParseTemplates_AllPagesCompile(t *testing.T) {
	s := &Server{}
	s.parseTemplates() // panics on any parse error
	if len(s.templates) == 0 {
		t.Fatal("parseTemplates loaded no pages")
	}
}

func TestParseTemplates_EveryTemplateFileRegistered(t *testing.T) {
	s := &Server{}
	s.parseTemplates()
	entries, err := fs.ReadDir(templatesFS, "templates")
	if err != nil {
		t.Fatalf("read embedded templates dir: %v", err)
	}
	for _, e := range entries {
		name := e.Name()
		// layout.html is the shared shell. Email templates live in pkg/notify.
		if e.IsDir() || name == "layout.html" || !strings.HasSuffix(name, ".html") {
			continue
		}
		if _, ok := s.templates[path.Base(name)]; !ok {
			t.Errorf("template file %q exists but is not listed in parseTemplates pages", name)
		}
	}
}

// The tenant delete form must carry the serial recovery override the devices
// page has, or a paired device with no usable fallback blocks the delete.
func TestAdminTenantsDeleteFormCarriesSerialRecovery(t *testing.T) {
	s := &Server{}
	s.parseTemplates()
	data := map[string]interface{}{
		"Rows":      []adminTenantRow{{Tenant: service.Tenant{ID: "gone"}}},
		"CSRFToken": "tok",
		"CSPNonce":  "nonce",
	}
	var buf bytes.Buffer
	if err := s.templates["admin-tenants.html"].ExecuteTemplate(&buf, "layout", data); err != nil {
		t.Fatal(err)
	}
	body := buf.String()
	start := strings.Index(body, `action="/admin/tenants/gone/delete"`)
	if start < 0 {
		t.Fatal("no delete form for the tenant")
	}
	form := body[start : start+strings.Index(body[start:], "</form>")]
	if !strings.Contains(form, `name="accept_serial_recovery" value="true"`) {
		t.Fatalf("tenant delete form has no accept_serial_recovery override:\n%s", form)
	}
}
