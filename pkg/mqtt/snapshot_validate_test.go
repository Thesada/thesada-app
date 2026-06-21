// Tests for validSnapshotContent. Driven by the forensic finding:
// config.json snapshots in production were misclassified shell output
// (fs.ls listings, ota.check ack strings) rather than real JSON.
package mqtt

import "testing"

func TestValidSnapshotContent_ConfigJSON(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"valid object", `{"device":{"name":"x"},"mqtt":{"port":8883}}`, true},
		{"valid pretty", "{\n  \"device\": {\"name\":\"x\"}\n}", true},
		{"empty", "", false},
		{"fs.ls output", "     148  /scripts/main.lua\n   10063  /scripts/rules.lua", false},
		{"ota.check ack", "ota.check queued (force=yes, url=config)\ncheck will run on next OTAUpdate::loop() tick", false},
		{"bare number", "42", false},
		{"bare string", `"hello"`, false},
		{"bare bool", "true", false},
		{"truncated", `{"device":{"name":"x"`, false},
		{"trailing junk after object", `{"a":1} extra log line`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validSnapshotContent("config.json", tc.content)
			if got != tc.want {
				t.Fatalf("validSnapshotContent(config.json, %q) = %v, want %v",
					tc.content, got, tc.want)
			}
		})
	}
}

func TestValidSnapshotContent_LuaScript(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"normal lua", "-- script\nlocal x = 1\nLog.info('boot')\n", true},
		{"empty", "", false},
		{"whitespace only", "   \n\t\n", false},
		{"shell usage", "Usage: fs.cat <path>", false},
		{"shell error", "Error: file not found", false},
		{"shell failed", "Failed to read /scripts/foo", false},
		{"unknown cmd", "Unknown command: zz  (type 'help')", false},
		{"comment with usage word inside", "-- describes a usage pattern\nlocal y = 2", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := validSnapshotContent("/scripts/foo.lua", tc.content)
			if got != tc.want {
				t.Fatalf("validSnapshotContent(/scripts/foo.lua, %q) = %v, want %v",
					tc.content, got, tc.want)
			}
		})
	}
}

func TestValidSnapshotContent_UnknownPathPermissive(t *testing.T) {
	// Future file types should not be silently rejected. The validator
	// only enforces shape on paths it knows about.
	if !validSnapshotContent("/data/foo.bin", "anything") {
		t.Fatal("unknown path should be permissive")
	}
}
