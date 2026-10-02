package web

import (
	"net/url"
	"testing"
)

func TestAdminFlashIgnoresUnregisteredText(t *testing.T) {
	q, err := url.ParseQuery("ok=you+have+been+hacked&error=%3Cscript%3E")
	if err != nil {
		t.Fatal(err)
	}
	ok, bad := adminFlash(q)
	if ok != "" || bad != "" {
		t.Fatalf("unregistered codes must render nothing, got %q %q", ok, bad)
	}
}

func TestAdminFlashRendersRegisteredText(t *testing.T) {
	q, err := url.ParseQuery(flashAdminDeleted.query() + "&" + flashAdminEnrollReset.query())
	if err != nil {
		t.Fatal(err)
	}
	ok, bad := adminFlash(q)
	if ok == "" || bad == "" {
		t.Fatalf("registered codes must render, got %q %q", ok, bad)
	}
	if ok == "deleted" || bad == "enroll_reset_failed" {
		t.Fatal("the page must show the text, not the code")
	}
}
