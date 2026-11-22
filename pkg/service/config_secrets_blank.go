// config_secrets_blank.go - strips plaintext device-config secrets out of
// config.json content before it is persisted to device_files / history. The
// real values live encrypted in device_config_secrets (pkg/secrets); the
// stored snapshot keeps the config shape with the sensitive leaves emptied so
// an operator never reads a secret back out of a snapshot, a history row, or
// the config editor.
//
// Two layers:
//   - explicit allowlist: the scalar secret fields (ScalarSecretFields), by
//     their dotted path into the nested config object.
//   - backstop: any leaf whose key looks sensitive (sensitiveConfigKeyRE),
//     which also covers each wifi.networks[].password. Mirrors the redaction
//     regex used for the super-admin config dump in pkg/web/admin_debug.go.
//
// The caller keeps the device-reported sha256 as the stored fingerprint;
// blanking changes only the content column, never the hash, so a blanked
// snapshot does not read as drift against the device.
package service

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// sensitiveConfigKeyRE matches a config leaf key whose value must never be
// persisted in cleartext. Long words match as a suffix (`api_key`, `passwd`),
// short ones only as the whole key or after _ . - (`sim_pin`, not `spin`).
// Same list as the firmware mask (config_mask_policy.h): a bare `pin` is a GPIO.
var sensitiveConfigKeyRE = regexp.MustCompile(`(?i)(password|passwd|secret|token|key|passphrase|credential|claim_code|(^|[_.-])(pass|pwd|psk|seed|sim_pin))$`)

// Masked firmware reads a secret field back as one of these, never its value.
// The device refuses to store either, so the exact strings are not secrets.
const (
	MaskSet   = "(set)"
	MaskEmpty = "(empty)"
)

// isMaskMarker reports whether v is exactly one of the read markers.
func isMaskMarker(v any) bool {
	s, ok := v.(string)
	return ok && (s == MaskSet || s == MaskEmpty)
}

// blankConfigSecrets returns config.json content with every sensitive leaf
// emptied (value -> ""), preserving the object shape and key set. It blanks
// the explicit SecretFields allowlist plus any leaf caught by the backstop
// regex. Content that is not a JSON object, or that has nothing to blank, is
// returned unchanged (byte-identical) so clean configs keep their exact form
// and hash; object-shaped ("{...") content that fails to parse returns an
// error (fail closed - never persist an unparseable secret-bearing blob).
// Output for a blanked config is re-serialized (indented, sorted
// keys) - deterministic, but the caller should not re-hash it: the stored
// sha256 stays the device fingerprint.
// in: raw config.json content. out: (possibly blanked) content, changed?, error.
func blankConfigSecrets(content string) (string, bool, error) {
	trimmed := strings.TrimSpace(content)
	if !strings.HasPrefix(trimmed, "{") {
		return content, false, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(trimmed), &m); err != nil {
		// Object-shaped ("{...") content that will not parse must fail closed:
		// returning it verbatim would persist plaintext secrets through the
		// Upsert chokepoint (AGENTS.md: reject silent fallbacks).
		return "", false, fmt.Errorf("blank config secrets: parse config.json: %w", err)
	}

	changed := false
	// Explicit allowlist first: guarantees the 4 scalar fields are blanked
	// even if the backstop regex is ever narrowed. Per-SSID WiFi passwords
	// live in the wifi.networks[] array and are covered by the backstop
	// (blankSensitiveLeaves recurses arrays and empties every password leaf).
	for _, dotted := range ScalarSecretFields {
		if blankPath(m, strings.Split(dotted, ".")) {
			changed = true
		}
	}
	// Backstop: any sensitive-looking scalar leaf anywhere in the tree.
	if blankSensitiveLeaves(m) {
		changed = true
	}
	if !changed {
		return content, false, nil
	}

	out, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "", false, err
	}
	return string(out), true, nil
}

// extractConfigSecrets pulls the plaintext values of the known secret fields
// out of config.json content, for backfilling existing devices into the
// encrypted store. Returns storage-field -> value for every scalar field
// present with a non-empty leaf, plus one wifi.password:<ssid> entry for each
// wifi.networks[] element that carries a non-empty password. Missing / empty /
// already-blanked leaves are omitted. Non-object content yields an empty map.
// The keys are storage keys ready for SetSecret.
// in: config.json content. out: field -> plaintext value.
func extractConfigSecrets(content string) map[string]string {
	out := make(map[string]string)
	var m map[string]any
	// A parse failure returns nothing to migrate, which is safe: every caller
	// pairs this with blankConfigSecrets, and that path fails closed on
	// unparseable object content, so a corrupt config never silently persists
	// its plaintext. Extraction is best-effort; blanking is the guard.
	if json.Unmarshal([]byte(content), &m) != nil {
		return out
	}
	for _, dotted := range ScalarSecretFields {
		if v, ok := readPath(m, strings.Split(dotted, ".")); ok && v != "" && !isMaskMarker(v) {
			out[dotted] = v
		}
	}
	for _, ssid := range WifiNetworkSSIDs(m) {
		if pw, ok := wifiNetworkPassword(m, ssid); ok && pw != "" && !isMaskMarker(pw) {
			out[WifiSecretField(ssid)] = pw
		}
	}
	return out
}

// WifiNetworkSSIDs returns the SSID of every wifi.networks[] entry that has a
// non-empty ssid, in config order. out: SSIDs (may be empty).
func WifiNetworkSSIDs(m map[string]any) []string {
	var out []string
	for _, net := range wifiNetworks(m) {
		if ssid, _ := net["ssid"].(string); ssid != "" {
			out = append(out, ssid)
		}
	}
	return out
}

// wifiNetworkPassword returns the plaintext password of the first
// wifi.networks[] entry whose ssid matches. out: password, found.
func wifiNetworkPassword(m map[string]any, ssid string) (string, bool) {
	for _, net := range wifiNetworks(m) {
		if s, _ := net["ssid"].(string); s == ssid {
			pw, ok := net["password"].(string)
			return pw, ok
		}
	}
	return "", false
}

// wifiNetworks returns the wifi.networks[] array as objects, skipping any
// non-object element. out: network objects (may be empty).
func wifiNetworks(m map[string]any) []map[string]any {
	wifi, _ := m["wifi"].(map[string]any)
	arr, _ := wifi["networks"].([]any)
	out := make([]map[string]any, 0, len(arr))
	for _, e := range arr {
		if net, ok := e.(map[string]any); ok {
			out = append(out, net)
		}
	}
	return out
}

// readPath walks segs into nested objects and returns the final string leaf.
// The inverse of blankPath. out: value, ok (false if any segment missing or
// the leaf is not a string).
func readPath(m map[string]any, segs []string) (string, bool) {
	cur := m
	for i, seg := range segs {
		if i == len(segs)-1 {
			s, ok := cur[seg].(string)
			return s, ok
		}
		child, ok := cur[seg].(map[string]any)
		if !ok {
			return "", false
		}
		cur = child
	}
	return "", false
}

// blankPath walks segs into nested objects and empties the final scalar
// string leaf if present and non-empty. Returns whether it blanked anything.
func blankPath(m map[string]any, segs []string) bool {
	if len(segs) == 0 {
		return false
	}
	key := segs[0]
	if len(segs) == 1 {
		s, ok := m[key].(string)
		if !ok || s == "" {
			return false
		}
		m[key] = ""
		return true
	}
	child, ok := m[key].(map[string]any)
	if !ok {
		return false
	}
	return blankPath(child, segs[1:])
}

// blankSensitiveLeaves recurses maps and arrays, emptying any non-empty
// string leaf whose key matches sensitiveConfigKeyRE. Non-string values are
// recursed into, never blanked wholesale, so an object keyed "credentials"
// keeps its structure while its inner secret leaves are cleared.
func blankSensitiveLeaves(v any) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if s, ok := val.(string); ok {
				if s != "" && sensitiveConfigKeyRE.MatchString(k) {
					t[k] = ""
					changed = true
				}
				continue
			}
			if blankSensitiveLeaves(val) {
				changed = true
			}
		}
	case []any:
		for _, item := range t {
			if blankSensitiveLeaves(item) {
				changed = true
			}
		}
	}
	return changed
}

// primaryWifiSSID is the first configured SSID, the one provisioning gives the legacy
// bare wifi.password. out: "" when none or the content does not parse.
func primaryWifiSSID(content string) string {
	var m map[string]any
	if json.Unmarshal([]byte(content), &m) != nil {
		return ""
	}
	if ssids := WifiNetworkSSIDs(m); len(ssids) > 0 {
		return ssids[0]
	}
	return ""
}

// openWifiSSIDs returns the SSID of every wifi.networks[] entry whose password
// is an explicit "" or reads (empty), in config order. A device read records these as open (#88).
// in: config.json content. out: SSIDs (may be empty).
func openWifiSSIDs(content string) []string {
	var m map[string]any
	if json.Unmarshal([]byte(content), &m) != nil {
		return nil
	}
	var out []string
	for _, net := range wifiNetworks(m) {
		ssid, _ := net["ssid"].(string)
		if pw, ok := net["password"].(string); ok && (pw == "" || pw == MaskEmpty) && ssid != "" && !slices.Contains(out, ssid) {
			out = append(out, ssid)
		}
	}
	return out
}

// BlankSecretFields lists the empty secret leaves in config.json content, the
// shape blankConfigSecrets leaves in snapshots and the editor. Writing such
// content to a device erases those secrets unless the field really is empty
// on the device. fields are storage keys (scalars and wifi.password:<ssid>),
// unknown are the dotted paths of empty sensitive leaves the store has no field for.
// Content that is not one JSON object fails closed with an error: a config.json
// write must never replace the device config with something it cannot parse.
// in: raw config.json content. out: empty fields, unknown empty leaves (sorted), error.
func BlankSecretFields(content string) ([]string, []string, error) {
	var m map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(content)), &m); err != nil {
		return nil, nil, fmt.Errorf("config.json must be one JSON object: %w", err)
	}
	if m == nil {
		return nil, nil, fmt.Errorf("config.json must be one JSON object, got null")
	}
	var fields []string
	for _, dotted := range ScalarSecretFields {
		segs := strings.Split(dotted, ".")
		if emptyLeafAt(m, segs) {
			fields = append(fields, dotted)
			deletePath(m, segs)
		}
	}
	for _, net := range wifiNetworks(m) {
		pw, ok := net["password"]
		ssid, _ := net["ssid"].(string)
		if ok && emptyValue(pw) && ssid != "" {
			fields = append(fields, WifiSecretField(ssid))
			delete(net, "password")
		}
	}
	// Whatever empty sensitive leaf is left has no storage field.
	var unknown []string
	blankSensitivePaths(m, "", &unknown)
	sort.Strings(unknown)
	return fields, unknown, nil
}

// emptyValue: "" or null, both of which the firmware reads as an empty string,
// or a read marker, which the app sends as "".
func emptyValue(v any) bool { return v == nil || v == "" || isMaskMarker(v) }

// emptyLeafAt reports whether the leaf at segs is present and empty or null.
func emptyLeafAt(m map[string]any, segs []string) bool {
	for _, seg := range segs[:len(segs)-1] {
		child, ok := m[seg].(map[string]any)
		if !ok {
			return false
		}
		m = child
	}
	v, ok := m[segs[len(segs)-1]]
	return ok && emptyValue(v)
}

// deletePath removes the leaf at segs, the counterpart of readPath.
func deletePath(m map[string]any, segs []string) {
	for _, seg := range segs[:len(segs)-1] {
		child, ok := m[seg].(map[string]any)
		if !ok {
			return
		}
		m = child
	}
	delete(m, segs[len(segs)-1])
}

// blankSensitivePaths appends the dotted path of every empty or null leaf whose key looks sensitive.
// Array elements show as [i]. in: value, its path, out list.
func blankSensitivePaths(v any, at string, out *[]string) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			p := k
			if at != "" {
				p = at + "." + k
			}
			if s, ok := val.(string); ok || val == nil {
				if (s == "" || isMaskMarker(s)) && sensitiveConfigKeyRE.MatchString(k) {
					*out = append(*out, p)
				}
				continue
			}
			blankSensitivePaths(val, p, out)
		}
	case []any:
		for i, item := range t {
			blankSensitivePaths(item, fmt.Sprintf("%s[%d]", at, i), out)
		}
	}
}

// walkSecretLeaves calls fn for every value under a sensitive key, in maps and
// arrays, with the map holding it. Values under other keys are walked into.
func walkSecretLeaves(v any, fn func(m map[string]any, k string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if sensitiveConfigKeyRE.MatchString(k) {
				fn(t, k)
				continue
			}
			walkSecretLeaves(val, fn)
		}
	case []any:
		for _, item := range t {
			walkSecretLeaves(item, fn)
		}
	}
}

// decodeConfig parses config.json content with numbers kept as written. out: tree, ok.
func decodeConfig(content string) (any, bool) {
	dec := json.NewDecoder(strings.NewReader(content))
	dec.UseNumber()
	var v any
	if dec.Decode(&v) != nil || dec.More() {
		return nil, false
	}
	return v, true
}

// HasMaskMarker reports whether config.json content holds a read marker under a
// secret key, so it is a masked read. in: content. out: masked.
func HasMaskMarker(content string) bool {
	v, ok := decodeConfig(content)
	if !ok {
		return false
	}
	found := false
	walkSecretLeaves(v, func(m map[string]any, k string) {
		found = found || isMaskMarker(m[k])
	})
	return found
}

// BlankMaskMarkers returns content with every marker under a secret key sent as
// "", so neither firmware generation stores a marker as a value. Content without
// one, or that does not parse, comes back unchanged. in: content. out: content.
func BlankMaskMarkers(content string) string {
	v, ok := decodeConfig(content)
	if !ok {
		return content
	}
	changed := false
	walkSecretLeaves(v, func(m map[string]any, k string) {
		if isMaskMarker(m[k]) {
			m[k] = ""
			changed = true
		}
	})
	if !changed {
		return content
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return content
	}
	return string(out)
}

// maskLikeFirmware replaces every non-null value under a secret key with the
// marker the firmware serves for it: (empty) for "", (set) for anything else.
func maskLikeFirmware(v any) {
	walkSecretLeaves(v, func(m map[string]any, k string) {
		switch m[k] {
		case nil:
		case "":
			m[k] = MaskEmpty
		default:
			m[k] = MaskSet
		}
	})
}

// MaskedConfigEqual reports whether served, a masked copy the firmware read
// back, is written once masked the same way. Numbers compare by value, as the
// firmware prints them again. in: written content, served copy. out: equal.
func MaskedConfigEqual(written, served string) bool {
	var w, s any
	if json.Unmarshal([]byte(written), &w) != nil || json.Unmarshal([]byte(served), &s) != nil {
		return false
	}
	if _, ok := w.(map[string]any); !ok {
		return false
	}
	maskLikeFirmware(w)
	return reflect.DeepEqual(w, s)
}
