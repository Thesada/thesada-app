// Template registration audit. parseTemplates panics (template.Must) on a
// syntax error, so calling it here fails the suite the moment a template
// breaks - the server would refuse to boot with the same panic. The second
// test closes the other gap: a template file added on disk but never
// listed in parseTemplates would silently 500 at render time with
// "template not found".
package web

import (
	"io/fs"
	"path"
	"strings"
	"testing"
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
		// layout.html is the shared shell, emails/ pairs are parsed via
		// renderEmail's own map - only page templates must be registered.
		if e.IsDir() || name == "layout.html" || !strings.HasSuffix(name, ".html") {
			continue
		}
		if _, ok := s.templates[path.Base(name)]; !ok {
			t.Errorf("template file %q exists but is not listed in parseTemplates pages", name)
		}
	}
}
