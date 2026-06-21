// Cache + clear-flow tests for the firmware-published retained-topics
// manifest. Pure-function coverage of the
// JSON parse + cache shape; the broker round trip in ClearDeviceRetained
// needs a paho mock and lives in the integration tier.
package mqtt

import (
	"reflect"
	"testing"
)

func TestCacheRetainedManifest_StoreUpdateClearRetrieve(t *testing.T) {
	c := &Client{}

	// Empty cache returns nil.
	if got := c.GetRetainedManifest("thesada/default/sht31"); got != nil {
		t.Fatalf("expected nil for unknown prefix, got %v", got)
	}

	// Store: well-formed JSON array lands under the topic prefix key.
	c.cacheRetainedManifest("thesada/default/sht31",
		[]byte(`["thesada/default/sht31/status","thesada/default/sht31/info","homeassistant/sensor/sht31/sht31_temp/config"]`))
	want := []string{
		"thesada/default/sht31/status",
		"thesada/default/sht31/info",
		"homeassistant/sensor/sht31/sht31_temp/config",
	}
	got := c.GetRetainedManifest("thesada/default/sht31")
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot mismatch:\n got: %v\nwant: %v", got, want)
	}

	// Defensive copy: mutating the returned slice must not corrupt the cache.
	got[0] = "MUTATED"
	again := c.GetRetainedManifest("thesada/default/sht31")
	if again[0] == "MUTATED" {
		t.Fatalf("GetRetainedManifest must return a defensive copy")
	}

	// Update: a fresh manifest replaces the prior list.
	c.cacheRetainedManifest("thesada/default/sht31",
		[]byte(`["thesada/default/sht31/status"]`))
	got = c.GetRetainedManifest("thesada/default/sht31")
	if len(got) != 1 || got[0] != "thesada/default/sht31/status" {
		t.Fatalf("update did not replace cache: %v", got)
	}

	// Clear: empty payload (broker delete-retained) drops the cache entry.
	c.cacheRetainedManifest("thesada/default/sht31", []byte{})
	if got := c.GetRetainedManifest("thesada/default/sht31"); got != nil {
		t.Fatalf("expected nil after empty-retained clear, got %v", got)
	}
}

func TestCacheRetainedManifest_MalformedPayloadIsIgnored(t *testing.T) {
	c := &Client{}
	c.cacheRetainedManifest("thesada/default/sht31",
		[]byte(`["thesada/default/sht31/status"]`))
	// Bad JSON: previous snapshot must be preserved (we don't trust the device
	// to overwrite a known-good manifest with garbage).
	c.cacheRetainedManifest("thesada/default/sht31", []byte(`{not json`))
	got := c.GetRetainedManifest("thesada/default/sht31")
	if len(got) != 1 || got[0] != "thesada/default/sht31/status" {
		t.Fatalf("malformed payload should not clobber cache: %v", got)
	}
}

func TestCacheRetainedManifest_PerDeviceIsolation(t *testing.T) {
	c := &Client{}
	c.cacheRetainedManifest("thesada/default/owb",
		[]byte(`["thesada/default/owb/status"]`))
	c.cacheRetainedManifest("thesada/acme/cyd",
		[]byte(`["thesada/acme/cyd/status","thesada/acme/cyd/info"]`))
	if got := c.GetRetainedManifest("thesada/default/owb"); len(got) != 1 {
		t.Fatalf("owb manifest lost: %v", got)
	}
	if got := c.GetRetainedManifest("thesada/acme/cyd"); len(got) != 2 {
		t.Fatalf("cyd manifest lost: %v", got)
	}
}
