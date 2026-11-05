package web

import (
	"net/url"
	"strings"
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

func TestAdminFlashRendersEveryRegisteredError(t *testing.T) {
	q, err := url.ParseQuery(flashAdminEnrollReset.query() + "&" + flashAdminBrokerLive.query() + "&error=nope")
	if err != nil {
		t.Fatal(err)
	}
	_, bad := adminFlash(q)
	for _, f := range []adminFlashCode{flashAdminEnrollReset, flashAdminBrokerLive} {
		if !strings.Contains(bad, adminFlashText["error"][f.code]) {
			t.Errorf("error text %q misses %s", bad, f.code)
		}
	}
}
