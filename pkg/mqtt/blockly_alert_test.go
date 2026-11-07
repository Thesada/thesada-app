package mqtt

import (
	"encoding/json"
	"errors"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	lua "github.com/yuin/gopher-lua"
)

// blocklyPreamble pulls the generated Lua preamble out of the editor JS.
func blocklyPreamble(t *testing.T) string {
	t.Helper()
	src, err := os.ReadFile("../web/static/js/blockly-rules.js")
	if err != nil {
		t.Fatal(err)
	}
	block := regexp.MustCompile(`(?s)var PREAMBLE = \[\n(.*?)\n\s*\]\.join\("\\n"\);`).FindSubmatch(src)
	if block == nil {
		t.Fatal("PREAMBLE array not found in blockly-rules.js")
	}
	var lines []string
	for _, raw := range strings.Split(string(block[1]), "\n") {
		lit := strings.TrimSuffix(strings.TrimSpace(raw), ",")
		if lit == "" {
			continue
		}
		lines = append(lines, jsString(t, lit))
	}
	out := strings.Join(lines, "\n")
	if !strings.Contains(out, "local function notify(msg, key)") {
		t.Fatal("preamble has no notify()")
	}
	return out
}

// jsString decodes one JS string literal, single or double quoted.
func jsString(t *testing.T, lit string) string {
	t.Helper()
	if len(lit) < 2 || (lit[0] != '"' && lit[0] != '\'') || lit[len(lit)-1] != lit[0] {
		t.Fatalf("not a JS string literal: %s", lit)
	}
	var b strings.Builder
	body := lit[1 : len(lit)-1]
	for i := 0; i < len(body); i++ {
		switch c := body[i]; {
		case c == '\\' && i+1 < len(body):
			i++
			if body[i] == '\'' {
				b.WriteByte('\'')
			} else {
				b.WriteByte('\\')
				b.WriteByte(body[i])
			}
		case c == '"':
			b.WriteString(`\"`)
		default:
			b.WriteByte(c)
		}
	}
	s, err := strconv.Unquote(`"` + b.String() + `"`)
	if err != nil {
		t.Fatalf("decode %s: %v", lit, err)
	}
	return s
}

// runNotify runs the preamble with stubbed device bindings, then notify(msg, key).
func runNotify(t *testing.T, msg, key string) (topic, payload, telegram string) {
	t.Helper()
	L := lua.NewState()
	defer L.Close()
	deviceLibs(L)
	noop := func(*lua.LState) int { return 0 }
	lib := func(name string, fns map[string]lua.LGFunction) {
		L.SetGlobal(name, L.SetFuncs(L.NewTable(), fns))
	}
	lib("Log", map[string]lua.LGFunction{"info": noop, "warn": noop, "error": noop})
	lib("Node", map[string]lua.LGFunction{"uptime": func(L *lua.LState) int { L.Push(lua.LNumber(1000)); return 1 }})
	lib("Config", map[string]lua.LGFunction{"get": func(L *lua.LState) int {
		switch L.CheckString(1) {
		case "mqtt.topic_prefix":
			L.Push(lua.LString("thesada/owb"))
		default:
			L.Push(lua.LNil)
		}
		return 1
	}})
	lib("MQTT", map[string]lua.LGFunction{"publish": func(L *lua.LState) int {
		topic, payload = L.CheckString(1), L.CheckString(2)
		return 0
	}})
	lib("Telegram", map[string]lua.LGFunction{"broadcast": func(L *lua.LState) int {
		telegram = L.CheckString(1)
		L.Push(lua.LTrue)
		return 1
	}})
	L.SetGlobal("MSG", lua.LString(msg))
	L.SetGlobal("KEY", lua.LString(key))
	if err := L.DoString(blocklyPreamble(t) + "\nnotify(MSG, KEY)\n"); err != nil {
		t.Fatal(err)
	}
	return topic, payload, telegram
}

// deviceQueueSlot mirrors fw MQTTClient.h MQTTMessage.payload[256]: enqueue rejects this many bytes or more.
const deviceQueueSlot = 256

func TestBlocklyNotify_PublishesAlertHandleAlertAccepts(t *testing.T) {
	long := strings.Repeat(`say "x" \ `, 40)
	cases := []struct {
		name, msg, key, wantMsg, wantCode, rawHas string
		cut                                       bool
		wantLen                                   int
	}{
		{name: "plain", msg: "Battery low", key: "battery_low", wantMsg: "Battery low"},
		{name: "escapes", msg: "say \"hi\" \\ back\n\t\x01\x7f 85.5°C", key: `temp:sup"ply:>=85`,
			wantMsg: "say \"hi\" \\ back\n\t\x01\x7f 85.5°C", rawHas: `say \"hi\" \\ back\u000a\u0009\u0001\u007f 85.5°C`},
		{name: "drops NUL", msg: "a\x00b", key: "battery_low", wantMsg: "ab"},
		{name: "long quotes cut to the queue slot", msg: long, key: "temp:supply:>=85", cut: true},
		{name: "long utf8 cut on a character", msg: strings.Repeat("€", 100), key: "battery_low", cut: true},
		{name: "long key cut to 64 bytes", msg: "Battery low", key: strings.Repeat("k", 100),
			wantMsg: "Battery low", wantCode: strings.Repeat("k", 64)},
		{name: "exact fit is not cut", msg: strings.Repeat("a", 202), key: "battery_low",
			wantMsg: strings.Repeat("a", 202), wantLen: deviceQueueSlot - 1},
		{name: "an escape that does not fit ends the message", msg: strings.Repeat("a", 201) + `"b`,
			key: "battery_low", wantMsg: strings.Repeat("a", 201)},
		{name: "quote before a stray continuation byte", msg: "x\"\x80y", key: "battery_low",
			wantMsg: "x\"\uFFFDy", rawHas: `x\"`},
		{name: "backslash before a stray continuation byte", msg: "x\\\x80y", key: "battery_low",
			wantMsg: "x\\\uFFFDy", rawHas: `x\\`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			topic, payload, telegram := runNotify(t, tc.msg, tc.key)
			if topic != "thesada/owb/alert" {
				t.Fatalf("topic = %q", topic)
			}
			if !strings.Contains(payload, tc.rawHas) {
				t.Fatalf("payload %s lacks %s", payload, tc.rawHas)
			}
			if tc.wantLen != 0 && len(payload) != tc.wantLen {
				t.Fatalf("payload is %d bytes, want %d: %s", len(payload), tc.wantLen, payload)
			}
			if len(payload) >= deviceQueueSlot {
				t.Fatalf("payload is %d bytes, the device queue drops it: %s", len(payload), payload)
			}
			sev, code, msg, err := parseAlert([]byte(payload))
			if err != nil {
				t.Fatalf("parseAlert(%s): %v", payload, err)
			}
			wantCode := tc.wantCode
			if wantCode == "" {
				wantCode = tc.key
			}
			if sev != "warn" || code != wantCode {
				t.Fatalf("got severity=%q code=%q from %s", sev, code, payload)
			}
			if tc.cut {
				if len(payload) < deviceQueueSlot-7 || !strings.HasPrefix(tc.msg, msg) || !utf8.ValidString(msg) {
					t.Fatalf("cut message %q (%d B payload) is not a whole-character prefix filling the slot", msg, len(payload))
				}
			} else if msg != tc.wantMsg {
				t.Fatalf("message = %q, want %q", msg, tc.wantMsg)
			}
			if telegram != tc.msg {
				t.Fatalf("telegram got %q, want the full plain message", telegram)
			}
		})
	}
}

func TestParseAlert_RejectsPlainTextAndBadSeverity(t *testing.T) {
	var syntax *json.SyntaxError
	if _, _, _, err := parseAlert([]byte("Battery low")); !errors.As(err, &syntax) {
		t.Fatalf("plain text: err = %v, want a JSON syntax error", err)
	}
	if _, _, _, err := parseAlert([]byte(`{"value":"Battery low [heap=1]"}`)); !errors.Is(err, errAlertSeverity) {
		t.Fatalf("missing severity: err = %v, want errAlertSeverity", err)
	}
}
