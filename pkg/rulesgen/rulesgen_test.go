package rulesgen

import (
	"encoding/json"
	"errors"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// ws builds a Blockly JSON workspace with one root holding the given rules.
func ws(t *testing.T, rules ...map[string]any) string {
	t.Helper()
	var chain map[string]any
	for i := len(rules) - 1; i >= 0; i-- {
		b := map[string]any{"type": RuleBlock, "id": "r", "fields": rules[i]}
		if chain != nil {
			b["next"] = map[string]any{"block": chain}
		}
		chain = b
	}
	root := map[string]any{"type": RootBlock, "id": "root", "x": 10, "y": 10}
	if chain != nil {
		root["inputs"] = map[string]any{"RULES": map[string]any{"block": chain}}
	}
	out, err := json.Marshal(map[string]any{"blocks": map[string]any{"languageVersion": 0, "blocks": []any{root}}})
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

func rule(metric, sensor, op string, value any, n, min any, msg, code string, cd any) map[string]any {
	return map[string]any{"METRIC": metric, "SENSOR": sensor, "OP": op, "VALUE": value,
		"SUSTAIN_N": n, "SUSTAIN_MIN": min, "MSG": msg, "CODE": code, "COOLDOWN_MIN": cd}
}

var sample = []map[string]any{
	rule("temperature", "Outdoor", "below", 2, 5, 5, "Freeze risk", "freeze", 15),
	rule("temperature", "", "above", "85", 3, 0, "Overheat", "overheat", 30),
	rule("current", "pump", "below", 0.5, 5, 0, "Pump not running", "pump", 60),
	rule("battery", "ignored", "below", 20, 1, 0, "Battery low", "battery_low", 120),
}

func TestGenerate_Golden(t *testing.T) {
	cases := map[string]string{
		"sample": ws(t, sample...),
		"empty":  ws(t),
		"hostile": ws(t, rule("temperature", "a\"]]\n\\\x01b", "above", 1, 1, 0,
			"x\" .. os.exit() .. \"]] --[[\r\t\x7f", "evil", 1)),
	}
	for name, w := range cases {
		rules, err := Parse(w)
		if err != nil {
			t.Fatalf("%s: parse: %v", name, err)
		}
		got := Generate(rules)
		path := filepath.Join("testdata", name+".lua")
		if *update {
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: read golden (run with -update): %v", name, err)
		}
		if got != string(want) {
			t.Errorf("%s: generated Lua differs from %s", name, path)
		}
	}
}

func TestParse_Refuses(t *testing.T) {
	ok := rule("temperature", "x", "above", 1, 1, 0, "m", "c", 1)
	mut := func(k string, v any) map[string]any {
		r := map[string]any{}
		for kk, vv := range ok {
			r[kk] = vv
		}
		if v == nil {
			delete(r, k)
		} else {
			r[k] = v
		}
		return r
	}
	cases := map[string]string{
		"not json":         "{",
		"unknown metric":   ws(t, mut("METRIC", "humidity")),
		"bad op":           ws(t, mut("OP", ">=")),
		"value text":       ws(t, mut("VALUE", "ten")),
		"value huge":       ws(t, mut("VALUE", 1e9)),
		"readings zero":    ws(t, mut("SUSTAIN_N", 0)),
		"readings frac":    ws(t, mut("SUSTAIN_N", 1.5)),
		"minutes neg":      ws(t, mut("SUSTAIN_MIN", -1)),
		"empty message":    ws(t, mut("MSG", "  ")),
		"long message":     ws(t, mut("MSG", strings.Repeat("m", MaxMsgBytes+1))),
		"code upper":       ws(t, mut("CODE", "Freeze")),
		"code colon":       ws(t, mut("CODE", "a:b")),
		"cooldown zero":    ws(t, mut("COOLDOWN_MIN", 0)),
		"long sensor":      ws(t, mut("SENSOR", strings.Repeat("s", MaxSensorBytes+1))),
		"missing msg":      ws(t, mut("MSG", nil)),
		"foreign root":     `{"blocks":{"blocks":[{"type":"lua_raw"}]}}`,
		"two roots":        `{"blocks":{"blocks":[{"type":"` + RootBlock + `"},{"type":"` + RootBlock + `"}]}}`,
		"foreign in chain": `{"blocks":{"blocks":[{"type":"` + RootBlock + `","inputs":{"RULES":{"block":{"type":"controls_if"}}}}]}}`,
		"foreign loose":    `{"blocks":{"blocks":[{"type":"` + RuleBlock + `","next":{"block":{"type":"text"}}}]}}`,
	}
	for name, w := range cases {
		if _, err := Parse(w); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: err = %v, want ErrInvalid", name, err)
		}
	}
	too := make([]map[string]any, MaxRules+1)
	for i := range too {
		too[i] = ok
	}
	if _, err := Parse(ws(t, too...)); !errors.Is(err, ErrInvalid) {
		t.Errorf("%d rules: err = %v, want ErrInvalid", MaxRules+1, err)
	}
}

func TestParse_LooseRulesIgnoredAndBatterySensorDropped(t *testing.T) {
	w := `{"blocks":{"blocks":[{"type":"` + RuleBlock + `","fields":{}},{"type":"` + RootBlock +
		`","inputs":{"RULES":{"block":{"type":"` + RuleBlock + `","fields":{"METRIC":"battery","SENSOR":"x","OP":"below","VALUE":"20","SUSTAIN_N":"1","SUSTAIN_MIN":"0","MSG":"low","CODE":"bat","COOLDOWN_MIN":"5"}}}}}]}}`
	rules, err := Parse(w)
	if err != nil || len(rules) != 1 || rules[0].Sensor != "" || rules[0].Value != 20 {
		t.Fatalf("rules = %+v err = %v", rules, err)
	}
}

func TestLuaString_EscapesEverythingThatCouldEndTheLiteral(t *testing.T) {
	got := LuaString("a\"b\\c\nd\re\tf\x00g\x1fh\x7fi]]é")
	want := `"a\"b\\c\nd\re\tf\000g\031h\127i]]é"`
	if got != want {
		t.Fatalf("LuaString = %s, want %s", got, want)
	}
}

// TestGenerate_RunsUnderLua loads the generated script with mocked firmware
// bindings and checks sustain, cooldown, stale probes and the code per alert.
func TestGenerate_RunsUnderLua(t *testing.T) {
	lua, err := exec.LookPath("lua")
	if err != nil {
		t.Skip("lua not on PATH, skipping the generated-script run (install lua 5.4+ to run it)")
	}
	harness, err := os.ReadFile(filepath.Join("testdata", "harness.lua"))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := Parse(ws(t, sample...))
	if err != nil {
		t.Fatal(err)
	}
	hostile, err := Parse(ws(t, rule("temperature", "a\"]]\n\\\x01b", "above", 1, 1, 0,
		"x\" .. os.exit() .. \"]] --[[\r\t\x7f", "evil", 1)))
	if err != nil {
		t.Fatal(err)
	}
	scenarios := map[string]struct {
		rules  []Rule
		script string
	}{
		"freeze needs 5 readings then cools down": {rules, `
local cold = { sensors = { { name = "Outdoor", address = "28A", temp_c = 1, temp = 1 } } }
for i = 1, 4 do fire("temperature", cold); advance(1000) end
expect(#broadcasts == 0, "fired before 5 readings")
fire("temperature", cold)
expect(#broadcasts == 1, "no alert after 5 readings")
expect(broadcasts[1].code == "freeze", "code " .. tostring(broadcasts[1].code))
expect(broadcasts[1].msg == "Outdoor: 1C - Freeze risk", "msg " .. broadcasts[1].msg)
for i = 1, 10 do advance(1000); fire("temperature", cold) end
expect(#broadcasts == 1, "re-fired inside the 15 min cooldown")
advance(15 * 60000)
for i = 1, 5 do fire("temperature", cold) end
expect(#broadcasts == 2, "no alert after the cooldown")`},
		"minutes sustain fires before the readings": {rules, `
local cold = { sensors = { { name = "Outdoor", address = "28A", temp_c = 0, temp = 0 } } }
fire("temperature", cold); advance(5 * 60000); fire("temperature", cold)
expect(#broadcasts == 1, "5 minutes in the condition did not fire")`},
		"recovery and stale reset the streak": {rules, `
local cold = { sensors = { { name = "Outdoor", address = "28A", temp_c = 1, temp = 1 } } }
local warm = { sensors = { { name = "Outdoor", address = "28A", temp_c = 9, temp = 9 } } }
local stale = { sensors = { { name = "Outdoor", address = "28A", stale = true } } }
for i = 1, 4 do fire("temperature", cold) end
fire("temperature", warm)
for i = 1, 4 do fire("temperature", cold) end
fire("temperature", stale)
for i = 1, 4 do fire("temperature", cold) end
expect(#broadcasts == 0, "streak survived a recovery or a stale reading")`},
		"any-sensor rule, other names and other rules": {rules, `
fire("temperature", { sensors = { { name = "Boiler", address = "28B", temp_c = 90, temp = 194 } } })
fire("temperature", { sensors = { { name = "Boiler", address = "28B", temp_c = 90, temp = 194 } } })
fire("temperature", { sensors = { { name = "Boiler", address = "28B", temp_c = 90, temp = 194 } } })
expect(#broadcasts == 1 and broadcasts[1].code == "overheat", "overheat on any sensor")
for i = 1, 5 do fire("current", { channels = { { name = "pump", current_a = 0.1 } } }) end
expect(#broadcasts == 2 and broadcasts[2].code == "pump", "pump rule")
expect(broadcasts[2].msg == "pump: 0.1A - Pump not running", "pump msg " .. broadcasts[2].msg)
fire("battery", { present = true, percent = 15, voltage_v = 3.5 })
expect(#broadcasts == 3 and broadcasts[3].msg == "Battery 15% - Battery low", "battery")
fire("battery", { present = false })
expect(#broadcasts == 3, "absent battery alerted")`},
		"no Telegram falls back to one MQTT alert": {rules, `
Telegram = nil
for i = 1, 3 do fire("temperature", { sensors = { { name = "Boiler", address = "28B", temp_c = 90, temp = 90 } } }) end
expect(#publishes == 1, "publishes " .. #publishes)
expect(publishes[1].topic == "thesada/t/d/alert", "topic")
expect(publishes[1].payload == '{"severity":"warn","code":"overheat","message":"Boiler: 90C - Overheat"}', publishes[1].payload)`},
		"hostile strings stay data": {hostile, `
local name = "a\"]]\n\\\1b"
fire("temperature", { sensors = { { name = name, address = "x", temp_c = 5, temp = 5 } } })
expect(#broadcasts == 1, "hostile rule did not match its own sensor name")
expect(broadcasts[1].msg == name .. ": 5C - x\" .. os.exit() .. \"]] --[[\r\t\127", "msg " .. broadcasts[1].msg)
expect(broadcasts[1].code == "evil", "code")`},
	}
	dir := t.TempDir()
	for name, sc := range scenarios {
		f := filepath.Join(dir, strings.ReplaceAll(name, " ", "_")+".lua")
		src := string(harness) + "\n" + Generate(sc.rules) + "\n" + sc.script + "\nprint(\"OK\")\n"
		if err := os.WriteFile(f, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
		out, err := exec.Command(lua, f).CombinedOutput()
		if err != nil || !strings.HasSuffix(strings.TrimSpace(string(out)), "OK") {
			t.Errorf("%s: %v\n%s", name, err, out)
		}
	}
}
