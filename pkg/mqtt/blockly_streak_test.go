package mqtt

import (
	"os"
	"regexp"
	"strings"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

// sustainTemplate evaluates the sustained branch of the thesada_if_temp
// generator, a JS concatenation of string literals and variables, with vars.
func sustainTemplate(t *testing.T, vars map[string]string) string {
	t.Helper()
	src, err := os.ReadFile("../web/static/js/blockly-rules.js")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?s)Blockly\.Lua\["thesada_if_temp"\].*?if \(sustain\) \{\s*return \((.*?)\);\s*\}`).FindSubmatch(src)
	if m == nil {
		t.Fatal("sustained branch of thesada_if_temp not found")
	}
	expr := string(m[1])
	var out strings.Builder
	for i := 0; i < len(expr); {
		switch c := expr[i]; c {
		case ' ', '\n', '\t', '+':
			i++
		case '"', '\'':
			j := i + 1
			for ; j < len(expr) && expr[j] != c; j++ {
				if expr[j] == '\\' {
					j++
				}
			}
			out.WriteString(jsString(t, expr[i:j+1]))
			i = j + 1
		default:
			j := i
			for j < len(expr) && (expr[j] == '_' || expr[j] >= 'a' && expr[j] <= 'z' || expr[j] >= 'A' && expr[j] <= 'Z') {
				j++
			}
			v, ok := vars[expr[i:j]]
			if j == i || !ok {
				t.Fatalf("cannot evaluate %q in the sustained template", expr[i:])
			}
			out.WriteString(v)
			i = j
		}
	}
	return out.String()
}

// deviceLibs mirrors the device Lua fork, where string, table and math are
// plain strings and only string methods resolve.
func deviceLibs(L *lua.LState) {
	for _, lib := range []string{"string", "table", "math"} {
		L.SetGlobal(lib, lua.LString(lib))
	}
}

// runStreak runs the preamble plus one generated sustained rule (supply >= 85)
// over readings, nil meaning a stale probe, at the given uptimes. out: alerts fired.
func runStreak(t *testing.T, readings []*float64, at []float64) int {
	t.Helper()
	rule := sustainTemplate(t, map[string]string{
		"sensor": "supply", "keyLit": "temp:supply:>=85", "op": ">=", "thresh": "85",
		"branch": "      FIRED = FIRED + 1\n      set_cooldown(key)\n",
	})
	L := lua.NewState()
	defer L.Close()
	deviceLibs(L)
	noop := func(*lua.LState) int { return 0 }
	L.SetGlobal("Log", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{"info": noop, "warn": noop, "error": noop}))
	L.SetGlobal("Config", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{"get": func(L *lua.LState) int {
		L.Push(lua.LNil)
		return 1
	}}))
	var now float64
	L.SetGlobal("Node", L.SetFuncs(L.NewTable(), map[string]lua.LGFunction{"uptime": func(L *lua.LState) int {
		L.Push(lua.LNumber(now))
		return 1
	}}))
	L.SetGlobal("FIRED", lua.LNumber(0))
	chunk := blocklyPreamble(t) + "\nfunction ON_TEMP(data)\n" + rule + "end\n"
	if err := L.DoString(chunk); err != nil {
		t.Fatalf("generated rule does not load: %v\n%s", err, rule)
	}
	for i, r := range readings {
		now = at[i]
		probe := L.NewTable()
		probe.RawSetString("name", lua.LString("supply"))
		if r == nil {
			probe.RawSetString("stale", lua.LTrue)
		} else {
			probe.RawSetString("temp_c", lua.LNumber(*r))
		}
		sensors := L.NewTable()
		sensors.Append(probe)
		data := L.NewTable()
		data.RawSetString("sensors", sensors)
		if err := L.CallByParam(lua.P{Fn: L.GetGlobal("ON_TEMP"), Protect: true}, data); err != nil {
			t.Fatalf("reading %d: %v", i, err)
		}
	}
	return int(lua.LVAsNumber(L.GetGlobal("FIRED")))
}

func TestBlocklySustainedTemp_StaleReadingEndsTheStreak(t *testing.T) {
	over, under := 90.0, 70.0
	seq := func(parts ...[]*float64) []*float64 {
		var out []*float64
		for _, p := range parts {
			out = append(out, p...)
		}
		return out
	}
	rep := func(v *float64, n int) []*float64 {
		out := make([]*float64, n)
		for i := range out {
			out[i] = v
		}
		return out
	}
	every := func(n int, stepMs float64) []float64 {
		out := make([]float64, n)
		for i := range out {
			out[i] = 1000 + float64(i)*stepMs
		}
		return out
	}
	cases := []struct {
		name     string
		readings []*float64
		at       []float64
		want     int
	}{
		{"over, an hour stale, over", seq(rep(&over, 1), rep(nil, 60), rep(&over, 1)), every(62, 60000), 0},
		{"stale in the middle restarts the count", seq(rep(&over, 4), rep(nil, 1), rep(&over, 4)), every(9, 1000), 0},
		{"below threshold restarts the count", seq(rep(&over, 4), rep(&under, 1), rep(&over, 4)), every(9, 1000), 0},
		{"five readings over fire", rep(&over, 5), every(5, 1000), 1},
		{"five minutes over fire", rep(&over, 4), every(4, 120000), 1},
		{"five readings after a stale gap fire", seq(rep(&over, 2), rep(nil, 3), rep(&over, 5)), every(10, 1000), 1},
		// No event at all: a silent source (SHT31 on a failed read) or a pruned probe.
		{"over, an hour silent, over", rep(&over, 2), []float64{1000, 1000 + 3600000}, 0},
		{"silent hour after the interval is known", rep(&over, 3), []float64{1000, 61000, 61000 + 3600000}, 0},
		{"slow 10 min interval still fires", rep(&over, 3), every(3, 600000), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := runStreak(t, tc.readings, tc.at); got != tc.want {
				t.Fatalf("alerts = %d, want %d", got, tc.want)
			}
		})
	}
}
