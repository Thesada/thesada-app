package service

import (
	"encoding/json"
	"maps"
	"slices"
	"sort"
	"strings"
	"testing"
)

// leaf walks a dotted path into a parsed config object and returns the string
// value there (or "", false if missing / not a string).
func leaf(t *testing.T, m map[string]any, path ...string) (string, bool) {
	t.Helper()
	var cur any = m
	for _, p := range path {
		obj, ok := cur.(map[string]any)
		if !ok {
			return "", false
		}
		cur = obj[p]
	}
	s, ok := cur.(string)
	return s, ok
}

func TestBlankConfigSecrets(t *testing.T) {
	t.Run("blanks the five allowlisted fields and reports changed", func(t *testing.T) {
		in := `{
			"wifi": {"ssid": "home", "password": "wifi-secret", "ap_password": "ap-secret"},
			"mqtt": {"host": "broker", "port": 8883, "password": "mqtt-secret"},
			"telegram": {"chat_id": "123", "bot_token": "tg-secret"},
			"web": {"user": "admin", "password": "web-secret"},
			"device": {"name": "sensor-1"}
		}`
		out, changed, err := blankConfigSecrets(in)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if !changed {
			t.Fatal("changed = false, want true")
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(out), &m); err != nil {
			t.Fatalf("output not valid JSON: %v", err)
		}
		for _, tc := range []struct{ path []string }{
			{[]string{"wifi", "password"}},
			{[]string{"wifi", "ap_password"}},
			{[]string{"mqtt", "password"}},
			{[]string{"telegram", "bot_token"}},
			{[]string{"web", "password"}},
		} {
			if v, ok := leaf(t, m, tc.path...); !ok || v != "" {
				t.Errorf("%v = %q (ok=%v), want blank", tc.path, v, ok)
			}
		}
		// Non-secret fields survive untouched.
		if v, _ := leaf(t, m, "wifi", "ssid"); v != "home" {
			t.Errorf("wifi.ssid = %q, want home (non-secret preserved)", v)
		}
		if v, _ := leaf(t, m, "device", "name"); v != "sensor-1" {
			t.Errorf("device.name = %q, want sensor-1", v)
		}
		// Non-string non-secret survives (mqtt.port stays a number).
		if mqtt, ok := m["mqtt"].(map[string]any); !ok || mqtt["port"] != float64(8883) {
			t.Errorf("mqtt.port not preserved: %v", m["mqtt"])
		}
	})

	t.Run("backstop catches an unknown sensitive key", func(t *testing.T) {
		in := `{"cloud": {"api_key": "leak-me", "region": "us"}}`
		out, changed, err := blankConfigSecrets(in)
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v, want changed", changed, err)
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(out), &m)
		if v, _ := leaf(t, m, "cloud", "api_key"); v != "" {
			t.Errorf("cloud.api_key = %q, want blank (backstop)", v)
		}
		if v, _ := leaf(t, m, "cloud", "region"); v != "us" {
			t.Errorf("cloud.region = %q, want us", v)
		}
	})

	t.Run("already-clean config returns byte-identical and unchanged", func(t *testing.T) {
		in := `{"wifi":{"ssid":"home","password":""},"device":{"name":"x"}}`
		out, changed, err := blankConfigSecrets(in)
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if changed {
			t.Error("changed = true, want false (nothing to blank)")
		}
		if out != in {
			t.Errorf("clean config mutated:\n got %q\nwant %q", out, in)
		}
	})

	t.Run("non-object content passes through unchanged", func(t *testing.T) {
		for _, in := range []string{"", "not json", "[1,2,3]", "  garbage  "} {
			out, changed, err := blankConfigSecrets(in)
			if err != nil || changed || out != in {
				t.Errorf("in=%q -> out=%q changed=%v err=%v, want passthrough", in, out, changed, err)
			}
		}
	})

	t.Run("extractConfigSecrets pulls scalars + one per wifi network", func(t *testing.T) {
		in := `{
			"wifi": {
				"ap_password": "app",
				"networks": [
					{"ssid": "home", "password": "wp"},
					{"ssid": "barn", "password": "bp"},
					{"ssid": "open", "password": ""}
				]
			},
			"mqtt": {"password": "mp"},
			"telegram": {"bot_token": "tt"},
			"web": {"password": ""},
			"device": {"name": "x"}
		}`
		got := extractConfigSecrets(in)
		want := map[string]string{
			"wifi.ap_password":   "app",
			"wifi.password:home": "wp",
			"wifi.password:barn": "bp",
			"mqtt.password":      "mp",
			"telegram.bot_token": "tt",
			// web.password and the empty-password network are omitted
		}
		if len(got) != len(want) {
			t.Fatalf("got %d fields %v, want %d %v", len(got), got, len(want), want)
		}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("extract[%q] = %q, want %q", k, got[k], v)
			}
		}
		if _, present := got["wifi.password:open"]; present {
			t.Error("empty-password network should be omitted from extraction")
		}
	})

	t.Run("blank empties every wifi.networks[] password, keeps SSIDs", func(t *testing.T) {
		in := `{"wifi":{"networks":[{"ssid":"home","password":"wp"},{"ssid":"barn","password":"bp"}]}}`
		out, changed, err := blankConfigSecrets(in)
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v, want changed", changed, err)
		}
		if got := extractConfigSecrets(out); len(got) != 0 {
			t.Errorf("extract from blanked networks = %v, want empty", got)
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(out), &m)
		for _, ssid := range WifiNetworkSSIDs(m) {
			if ssid != "home" && ssid != "barn" {
				t.Errorf("unexpected SSID after blanking: %q", ssid)
			}
		}
		if ssids := WifiNetworkSSIDs(m); len(ssids) != 2 {
			t.Errorf("SSIDs after blanking = %v, want both preserved", ssids)
		}
	})

	t.Run("extractConfigSecrets on a blanked config yields nothing", func(t *testing.T) {
		blanked, _, _ := blankConfigSecrets(`{"wifi":{"password":"secret"},"mqtt":{"password":"secret"}}`)
		if got := extractConfigSecrets(blanked); len(got) != 0 {
			t.Errorf("extract from blanked = %v, want empty", got)
		}
	})

	t.Run("nested arrays of objects are walked", func(t *testing.T) {
		in := `{"peers":[{"name":"a","secret":"s1"},{"name":"b","secret":"s2"}]}`
		out, changed, err := blankConfigSecrets(in)
		if err != nil || !changed {
			t.Fatalf("changed=%v err=%v, want changed", changed, err)
		}
		var m map[string]any
		_ = json.Unmarshal([]byte(out), &m)
		peers, _ := m["peers"].([]any)
		for i, p := range peers {
			obj := p.(map[string]any)
			if obj["secret"] != "" {
				t.Errorf("peers[%d].secret = %v, want blank", i, obj["secret"])
			}
			if obj["name"] == "" {
				t.Errorf("peers[%d].name blanked, want preserved", i)
			}
		}
	})
}

// Empty secret leaves come back as storage fields, so the write guard can ask
// the store which of them are real open networks (#88). An empty sensitive
// leaf with no storage field is reported as unknown.
func TestBlankSecretFields(t *testing.T) {
	cases := []struct {
		content string
		fields  []string
		unknown bool
	}{
		{`{"mqtt":{"password":"","host":"b"}}`, []string{"mqtt.password"}, false},
		{`{"wifi":{"networks":[{"ssid":"home","password":""}]}}`, []string{"wifi.password:home"}, false},
		{`{"wifi":{"networks":[{"ssid":"a","password":"pw"},{"ssid":"b","password":""}]}}`, []string{"wifi.password:b"}, false},
		{`{"telegram":{"bot_token":""},"wifi":{"ap_password":""}}`, []string{"telegram.bot_token", "wifi.ap_password"}, false},
		{`{"wifi":{"networks":[{"password":""}]}}`, nil, true},
		{`{"ota":{"api_key":""}}`, nil, true},
		{`{"mqtt":{"password":"s3cret","host":"b"}}`, nil, false},
		{`{"mqtt":{"host":"b"}}`, nil, false},
		{`{"wifi":{"networks":[{"ssid":"home","password":"pw"}]},"web":{}}`, nil, false},
	}
	// Anything that is not one JSON object must never reach the device as config.json.
	for _, bad := range []string{`not json at all`, `[]`, `null`, `42`, `"x"`, ``, `{"mqtt":`} {
		if _, _, err := BlankSecretFields(bad); err == nil {
			t.Errorf("%q: want an error, got none", bad)
		}
	}
	for _, c := range cases {
		fields, unknown, err := BlankSecretFields(c.content)
		if err != nil {
			t.Fatalf("%s: %v", c.content, err)
		}
		sort.Strings(fields)
		if !slices.Equal(fields, c.fields) || (len(unknown) > 0) != c.unknown {
			t.Errorf("%s: got %v unknown=%v, want %v unknown=%v", c.content, fields, unknown, c.fields, c.unknown)
		}
	}
}

// A device read records a network open only for an explicit "" password (#88).
// Secrets never carry "": extractConfigSecrets skips every empty leaf.
func TestOpenWifiSSIDs(t *testing.T) {
	content := `{"mqtt":{"password":"m"},"web":{"password":""},` +
		`"wifi":{"networks":[{"ssid":"home","password":"pw"},{"ssid":"cafe","password":""},{"ssid":"lab"},{"password":""}]}}`
	if got := openWifiSSIDs(content); !slices.Equal(got, []string{"cafe"}) {
		t.Errorf("open = %v, want [cafe]", got)
	}
	want := map[string]string{"mqtt.password": "m", "wifi.password:home": "pw"}
	if got := extractConfigSecrets(content); !maps.Equal(got, want) {
		t.Errorf("secrets = %v, want %v", got, want)
	}
}

// Each entry counts on its own: an empty password after a set one for the same SSID is still open.
func TestOpenWifiSSIDs_RepeatedSSID(t *testing.T) {
	content := `{"wifi":{"networks":[{"ssid":"cafe","password":"pw"},{"ssid":"cafe","password":""},{"ssid":"cafe","password":""}]}}`
	if got := openWifiSSIDs(content); !slices.Equal(got, []string{"cafe"}) {
		t.Errorf("open = %v, want [cafe]", got)
	}
}

// The key pattern names the leaves snapshots blank and the write guard checks.
func TestSensitiveConfigKey(t *testing.T) {
	for _, k := range []string{
		"password", "ap_password", "bot_token", "client_secret", "api_key", "client_key",
		"passphrase", "credential", "pass", "web_pass", "pwd", "mqtt_pwd", "psk", "PSK",
		"sim_pin", "cellular_sim_pin", "seed", "wallet_seed", "passwd", "Password",
		"claim_code", "enroll_claim_code",
	} {
		if !sensitiveConfigKeyRE.MatchString(k) {
			t.Errorf("%q: want a match", k)
		}
	}
	for _, k := range []string{
		"ssid", "host", "bypass", "compass", "spin", "spinning", "pinout", "pins",
		"seeded", "proceed", "user", "chat_id", "port", "passive", "pass_through",
		"pin", "heartbeat_pin", "led_pin", "PIN", "code", "claim",
	} {
		if sensitiveConfigKeyRE.MatchString(k) {
			t.Errorf("%q: want no match", k)
		}
	}
}

// A null secret leaf reaches the firmware as "", so the guard counts it as empty.
func TestBlankSecretFields_NullIsEmpty(t *testing.T) {
	for _, c := range []struct {
		content string
		fields  []string
		unknown bool
	}{
		{`{"mqtt":{"password":null}}`, []string{"mqtt.password"}, false},
		{`{"wifi":{"networks":[{"ssid":"home","password":null}]}}`, []string{"wifi.password:home"}, false},
		{`{"cellular":{"sim_pin":null}}`, nil, true},
		{`{"lora":{"meshtastic":{"psk":""}}}`, nil, true},
	} {
		fields, unknown, err := BlankSecretFields(c.content)
		if err != nil {
			t.Fatalf("%s: %v", c.content, err)
		}
		sort.Strings(fields)
		if !slices.Equal(fields, c.fields) || (len(unknown) > 0) != c.unknown {
			t.Errorf("%s: got %v unknown=%v, want %v unknown=%v", c.content, fields, unknown, c.fields, c.unknown)
		}
	}
}

// The two firmware masked generations side by side: an old dump carries the
// values, a masked one only markers, and a marker is never a secret value.
func TestMaskMarkers_BothFirmwareGenerations(t *testing.T) {
	for _, c := range []struct {
		name, content string
		secrets       map[string]string
		open          []string
		marker        bool
	}{
		{"clear values", `{"mqtt":{"password":"m"},"wifi":{"networks":[{"ssid":"home","password":"pw"},{"ssid":"cafe","password":""}]}}`,
			map[string]string{"mqtt.password": "m", "wifi.password:home": "pw"}, []string{"cafe"}, false},
		{"masked", `{"mqtt":{"password":"(set)"},"web":{"password":"(empty)"},"wifi":{"networks":[{"ssid":"home","password":"(set)"},{"ssid":"cafe","password":"(empty)"}]}}`,
			map[string]string{}, []string{"cafe"}, true},
		{"marker inside a longer value is a value", `{"mqtt":{"password":"x(set)"},"wifi":{"networks":[{"ssid":"home","password":"(empty) "}]}}`,
			map[string]string{"mqtt.password": "x(set)", "wifi.password:home": "(empty) "}, nil, false},
		{"marker under a plain key is a value", `{"wifi":{"networks":[{"ssid":"(set)","password":"pw"}]},"device":{"name":"(empty)"}}`,
			map[string]string{"wifi.password:(set)": "pw"}, nil, false},
		{"case differs", `{"mqtt":{"password":"(SET)"}}`, map[string]string{"mqtt.password": "(SET)"}, nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := extractConfigSecrets(c.content); !maps.Equal(got, c.secrets) {
				t.Errorf("secrets = %v, want %v", got, c.secrets)
			}
			if got := openWifiSSIDs(c.content); !slices.Equal(got, c.open) {
				t.Errorf("open = %v, want %v", got, c.open)
			}
			if got := HasMaskMarker(c.content); got != c.marker {
				t.Errorf("HasMaskMarker = %v, want %v", got, c.marker)
			}
			blanked, _, err := blankConfigSecrets(c.content)
			if err != nil {
				t.Fatal(err)
			}
			if HasMaskMarker(blanked) {
				t.Errorf("stored form keeps a marker: %s", blanked)
			}
		})
	}
}

// A marker in a posted config counts as blank, so the device guard runs for it.
func TestBlankSecretFields_MarkerIsBlank(t *testing.T) {
	for _, c := range []struct {
		content string
		fields  []string
		unknown bool
	}{
		{`{"mqtt":{"password":"(set)"}}`, []string{"mqtt.password"}, false},
		{`{"web":{"password":"(empty)"}}`, []string{"web.password"}, false},
		{`{"wifi":{"networks":[{"ssid":"home","password":"(set)"}]}}`, []string{"wifi.password:home"}, false},
		{`{"cellular":{"sim_pin":"(set)"}}`, nil, true},
		{`{"mqtt":{"password":"(set)x"}}`, nil, false},
	} {
		fields, unknown, err := BlankSecretFields(c.content)
		if err != nil {
			t.Fatalf("%s: %v", c.content, err)
		}
		sort.Strings(fields)
		if !slices.Equal(fields, c.fields) || (len(unknown) > 0) != c.unknown {
			t.Errorf("%s: got %v unknown=%v, want %v unknown=%v", c.content, fields, unknown, c.fields, c.unknown)
		}
	}
}

// The app never sends a marker: each one under a secret key goes out as "".
func TestBlankMaskMarkers(t *testing.T) {
	in := `{"mqtt":{"password":"(set)","port":8883,"big":12345678901234567},"wifi":{"networks":[{"ssid":"(set)","password":"(empty)"}]},"lora":{"psk":"(set)"}}`
	out := BlankMaskMarkers(in)
	if HasMaskMarker(out) {
		t.Fatalf("marker left: %s", out)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	for _, p := range [][]string{{"mqtt", "password"}, {"lora", "psk"}} {
		if v, ok := leaf(t, m, p...); !ok || v != "" {
			t.Errorf("%v = %q, want blank", p, v)
		}
	}
	nets := m["wifi"].(map[string]any)["networks"].([]any)
	if net := nets[0].(map[string]any); net["ssid"] != "(set)" || net["password"] != "" {
		t.Errorf("network = %v, want ssid kept and password blank", net)
	}
	if !strings.Contains(out, "12345678901234567") {
		t.Errorf("number lost precision: %s", out)
	}
	for _, same := range []string{`{"mqtt":{"password":"s3cret"}}`, `{"mqtt":{"password":""}}`, `not json`, `{"device":{"name":"(set)"}}`} {
		if got := BlankMaskMarkers(same); got != same {
			t.Errorf("%s changed to %s", same, got)
		}
	}
}

// The firmware serves a config-shaped file masked and pretty printed. A copy
// is the written content when both mask to the same tree.
func TestMaskedConfigEqual(t *testing.T) {
	written := `{"mqtt":{"password":"","port":8883,"user":"u"},"wifi":{"networks":[{"ssid":"a","password":"pw"}]},"rate":0.5}`
	served := "{\n  \"mqtt\": {\n    \"password\": \"(empty)\",\n    \"port\": 8883,\n    \"user\": \"u\"\n  },\n" +
		"  \"wifi\": {\n    \"networks\": [\n      {\n        \"ssid\": \"a\",\n        \"password\": \"(set)\"\n      }\n    ]\n  },\n  \"rate\": 0.5\n}"
	if !MaskedConfigEqual(written, served) {
		t.Fatal("masked copy of the same config: want equal")
	}
	for name, other := range map[string]string{
		"plain value changed": strings.Replace(served, `"u"`, `"v"`, 1),
		"set for empty":       strings.Replace(served, `"(empty)"`, `"(set)"`, 1),
		"empty for set":       strings.Replace(served, `"password": "(set)"`, `"password": "(empty)"`, 1),
		"truncated":           served[:len(served)/2],
		"key missing":         strings.Replace(served, `"rate": 0.5`, `"other": 0.5`, 1),
		"clear value served":  strings.Replace(served, `"(set)"`, `"pw"`, 1),
	} {
		if MaskedConfigEqual(written, other) {
			t.Errorf("%s: want not equal", name)
		}
	}
	if MaskedConfigEqual("not json", "not json") {
		t.Error("non-JSON content: want not equal, the bytes compare already ran")
	}
}
