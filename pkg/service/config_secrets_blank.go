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
	"regexp"
	"strings"
)

// sensitiveConfigKeyRE matches a config leaf key whose value must never be
// persisted in cleartext. Anchored at the end so `password`, `api_key`,
// `bot_token`, `client_secret`, `passphrase`, `credential` all match.
var sensitiveConfigKeyRE = regexp.MustCompile(`(?i)(password|secret|token|key|passphrase|credential)$`)

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
		if v, ok := readPath(m, strings.Split(dotted, ".")); ok && v != "" {
			out[dotted] = v
		}
	}
	for _, ssid := range WifiNetworkSSIDs(m) {
		if pw, ok := wifiNetworkPassword(m, ssid); ok && pw != "" {
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
