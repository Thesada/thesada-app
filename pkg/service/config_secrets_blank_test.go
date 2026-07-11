package service

import (
	"encoding/json"
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
