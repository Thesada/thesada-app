// Package rulesgen turns a tenant rules workspace (Blockly JSON) into the
// device's /scripts/rules.lua. The server is the only generator: the browser
// sends blocks, never Lua, so a tenant cannot push arbitrary code.
//
// The output follows thesada-fw examples/scripts/rules.lua.example: sustain,
// per-key cooldown, and one alert per firing through Telegram.broadcast with
// an MQTT fallback when the Telegram module is absent. String methods only,
// because older firmware leaves the table and math globals as plain strings.
package rulesgen

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Block types the tenant editor offers. Anything else in a workspace is refused.
const (
	RootBlock = "thesada_tenant_rules"
	RuleBlock = "thesada_tenant_rule"
)

// Limits keep the script small and the fields readable on a phone.
const (
	MaxRules       = 32
	MaxSensorBytes = 40
	MaxMsgBytes    = 120
	MaxAbsValue    = 1e6
	MaxSustainN    = 1000
	MaxSustainMin  = 1440
	MaxCooldownMin = 1440
)

// Metric is the device event a rule listens to.
type Metric string

const (
	Temperature Metric = "temperature"
	Current     Metric = "current"
	Battery     Metric = "battery"
)

// Rule is one validated "when ... then notify" block.
type Rule struct {
	Metric      Metric
	Sensor      string // probe or channel name, "" = any. Unused for battery
	Above       bool   // true: value >= Value, false: value <= Value
	Value       float64
	SustainN    int // fire after N readings in a row
	SustainMin  int // or after M minutes in the condition, 0 = readings only
	Msg         string
	Code        string
	CooldownMin int
}

// ErrInvalid wraps every validation failure, so callers answer 400.
var ErrInvalid = errors.New("invalid rules")

var codeRe = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

type wsBlock struct {
	Type   string                     `json:"type"`
	Fields map[string]json.RawMessage `json:"fields"`
	Inputs map[string]struct {
		Block *wsBlock `json:"block"`
	} `json:"inputs"`
	Next *struct {
		Block *wsBlock `json:"block"`
	} `json:"next"`
}

type workspace struct {
	Blocks struct {
		Blocks []wsBlock `json:"blocks"`
	} `json:"blocks"`
}

// Parse validates a Blockly JSON workspace and returns its rules in order.
// Loose rule blocks outside the root are ignored, any other block type fails.
// in: workspace JSON. out: rules, error wrapping ErrInvalid.
func Parse(workspaceJSON string) ([]Rule, error) {
	var ws workspace
	if err := json.Unmarshal([]byte(workspaceJSON), &ws); err != nil {
		return nil, fmt.Errorf("%w: workspace is not JSON", ErrInvalid)
	}
	var root *wsBlock
	for i := range ws.Blocks.Blocks {
		b := &ws.Blocks.Blocks[i]
		switch b.Type {
		case RootBlock:
			if root != nil {
				return nil, fmt.Errorf("%w: more than one rules block", ErrInvalid)
			}
			root = b
		case RuleBlock:
			if err := checkTypes(b); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: unsupported block %q", ErrInvalid, b.Type)
		}
	}
	if root == nil {
		return nil, nil
	}
	var rules []Rule
	first := root.Inputs["RULES"].Block
	for b := first; b != nil; b = nextBlock(b) {
		if b.Type != RuleBlock {
			return nil, fmt.Errorf("%w: unsupported block %q", ErrInvalid, b.Type)
		}
		if len(rules) == MaxRules {
			return nil, fmt.Errorf("%w: more than %d rules", ErrInvalid, MaxRules)
		}
		r, err := parseRule(b, len(rules)+1)
		if err != nil {
			return nil, err
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func nextBlock(b *wsBlock) *wsBlock {
	if b.Next == nil {
		return nil
	}
	return b.Next.Block
}

// checkTypes walks a loose chain so a hidden foreign block cannot ride along.
func checkTypes(b *wsBlock) error {
	for ; b != nil; b = nextBlock(b) {
		if b.Type != RuleBlock {
			return fmt.Errorf("%w: unsupported block %q", ErrInvalid, b.Type)
		}
	}
	return nil
}

func parseRule(b *wsBlock, n int) (Rule, error) {
	bad := func(field, why string) (Rule, error) {
		return Rule{}, fmt.Errorf("%w: rule %d %s %s", ErrInvalid, n, field, why)
	}
	var r Rule
	metric, err := fieldString(b, "METRIC")
	if err != nil {
		return bad("metric", "missing")
	}
	switch Metric(metric) {
	case Temperature, Current, Battery:
		r.Metric = Metric(metric)
	default:
		return bad("metric", "unknown")
	}
	sensor, _ := fieldString(b, "SENSOR")
	if r.Metric != Battery {
		r.Sensor = strings.TrimSpace(sensor)
	}
	if !utf8.ValidString(r.Sensor) || len(r.Sensor) > MaxSensorBytes {
		return bad("sensor", fmt.Sprintf("must be text up to %d bytes", MaxSensorBytes))
	}
	op, _ := fieldString(b, "OP")
	switch op {
	case "above":
		r.Above = true
	case "below":
	default:
		return bad("comparison", "must be above or below")
	}
	if r.Value, err = fieldNumber(b, "VALUE"); err != nil || math.Abs(r.Value) > MaxAbsValue {
		return bad("value", "must be a number")
	}
	sn, err := fieldNumber(b, "SUSTAIN_N")
	if err != nil || sn != math.Trunc(sn) || sn < 1 || sn > MaxSustainN {
		return bad("readings", fmt.Sprintf("must be a whole number 1 to %d", MaxSustainN))
	}
	r.SustainN = int(sn)
	sm, err := fieldNumber(b, "SUSTAIN_MIN")
	if err != nil || sm != math.Trunc(sm) || sm < 0 || sm > MaxSustainMin {
		return bad("minutes", fmt.Sprintf("must be a whole number 0 to %d", MaxSustainMin))
	}
	r.SustainMin = int(sm)
	if r.Msg, err = fieldString(b, "MSG"); err != nil {
		return bad("message", "missing")
	}
	r.Msg = strings.TrimSpace(r.Msg)
	if r.Msg == "" || !utf8.ValidString(r.Msg) || len(r.Msg) > MaxMsgBytes {
		return bad("message", fmt.Sprintf("must be text up to %d bytes", MaxMsgBytes))
	}
	if r.Code, err = fieldString(b, "CODE"); err != nil || !codeRe.MatchString(r.Code) {
		return bad("code", "must be lowercase letters, digits or _, up to 32")
	}
	cd, err := fieldNumber(b, "COOLDOWN_MIN")
	if err != nil || cd != math.Trunc(cd) || cd < 1 || cd > MaxCooldownMin {
		return bad("cooldown", fmt.Sprintf("must be a whole number 1 to %d", MaxCooldownMin))
	}
	r.CooldownMin = int(cd)
	return r, nil
}

func fieldString(b *wsBlock, name string) (string, error) {
	raw, ok := b.Fields[name]
	if !ok {
		return "", errors.New("missing")
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", err
	}
	return s, nil
}

// fieldNumber accepts a JSON number or a numeric string, Blockly emits both.
func fieldNumber(b *wsBlock, name string) (float64, error) {
	raw, ok := b.Fields[name]
	if !ok {
		return 0, errors.New("missing")
	}
	var f float64
	if err := json.Unmarshal(raw, &f); err != nil {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			return 0, err
		}
		if f, err = strconv.ParseFloat(strings.TrimSpace(s), 64); err != nil {
			return 0, err
		}
	}
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, errors.New("not finite")
	}
	return f, nil
}

// LuaString quotes s as a Lua string literal. Quote, backslash and the usual
// whitespace escapes are named, every other control byte becomes \ddd.
// in: any string. out: a "..." literal that cannot end early or run code.
func LuaString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			b.WriteString(`\"`)
		case c == '\\':
			b.WriteString(`\\`)
		case c == '\n':
			b.WriteString(`\n`)
		case c == '\r':
			b.WriteString(`\r`)
		case c == '\t':
			b.WriteString(`\t`)
		case c < 0x20 || c == 0x7f:
			fmt.Fprintf(&b, `\%03d`, c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func luaNumber(f float64) string {
	return strconv.FormatFloat(f, 'g', -1, 64)
}
