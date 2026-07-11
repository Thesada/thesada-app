// Unit coverage for the pair-time secret-provision loop. The MQTT push and DB
// reveal are injected, so the ordering / skip / abort logic is tested in
// isolation (the handler wiring stays a thin adapter).
package web

import (
	"errors"
	"reflect"
	"testing"
)

func TestProvisionDeviceSecrets(t *testing.T) {
	// Legacy-shaped field list (bare wifi.password) to exercise the remap path.
	fields := []string{"wifi.password", "mqtt.password", "telegram.bot_token", "web.password", "wifi.ap_password"}

	t.Run("legacy wifi.password provisioned per-SSID, mqtt 1:1, skips unset", func(t *testing.T) {
		set := map[string]string{"wifi.password": "wp", "mqtt.password": "mp"}
		var pushed [][2]string
		out := provisionDeviceSecrets(fields, "HomeNet",
			func(f string) (string, bool, error) { v, ok := set[f]; return v, ok, nil },
			func(fw, v string) (string, bool) { pushed = append(pushed, [2]string{fw, v}); return "", true },
		)
		if out.AbortMsg != "" {
			t.Fatalf("AbortMsg = %q, want empty", out.AbortMsg)
		}
		want := [][2]string{{"wifi.password:HomeNet", "wp"}, {"mqtt.password", "mp"}}
		if !reflect.DeepEqual(pushed, want) {
			t.Errorf("pushed = %v, want %v", pushed, want)
		}
		if len(out.SkippedUnset) != 3 {
			t.Errorf("SkippedUnset = %v, want 3 (the unset fields)", out.SkippedUnset)
		}
	})

	t.Run("per-SSID wifi fields pass through unchanged", func(t *testing.T) {
		// The real multi-network path: storage field == firmware field, no remap.
		perSSID := []string{"wifi.password:HomeNet", "wifi.password:Barn"}
		set := map[string]string{"wifi.password:HomeNet": "hp", "wifi.password:Barn": "bp"}
		var pushed [][2]string
		out := provisionDeviceSecrets(perSSID, "HomeNet",
			func(f string) (string, bool, error) { v, ok := set[f]; return v, ok, nil },
			func(fw, v string) (string, bool) { pushed = append(pushed, [2]string{fw, v}); return "", true },
		)
		want := [][2]string{{"wifi.password:HomeNet", "hp"}, {"wifi.password:Barn", "bp"}}
		if out.AbortMsg != "" || !reflect.DeepEqual(pushed, want) {
			t.Errorf("multi-SSID: AbortMsg=%q pushed=%v, want %v", out.AbortMsg, pushed, want)
		}
	})

	t.Run("secretProvisionFields builds scalars + per-SSID + legacy", func(t *testing.T) {
		got, primary := secretProvisionFields([]string{"HomeNet", "Barn"})
		want := []string{"mqtt.password", "telegram.bot_token", "web.password", "wifi.ap_password",
			"wifi.password:HomeNet", "wifi.password:Barn", "wifi.password"}
		if !reflect.DeepEqual(got, want) || primary != "HomeNet" {
			t.Errorf("secretProvisionFields = %v, %q; want %v, HomeNet", got, primary, want)
		}
		if _, primary := secretProvisionFields(nil); primary != "" {
			t.Errorf("no-network primary = %q, want empty", primary)
		}
	})

	t.Run("wifi.password with no SSID is skipped, not pushed or fatal", func(t *testing.T) {
		var pushed []string
		out := provisionDeviceSecrets([]string{"wifi.password"}, "",
			func(f string) (string, bool, error) { return "wp", true, nil },
			func(fw, v string) (string, bool) { pushed = append(pushed, fw); return "", true },
		)
		if out.AbortMsg != "" || len(pushed) != 0 {
			t.Errorf("no-SSID: AbortMsg=%q pushed=%v, want clean skip", out.AbortMsg, pushed)
		}
		if !reflect.DeepEqual(out.SkippedNoSSID, []string{"wifi.password"}) {
			t.Errorf("SkippedNoSSID = %v, want [wifi.password]", out.SkippedNoSSID)
		}
	})

	t.Run("reveal error aborts immediately, before any later field", func(t *testing.T) {
		var reveals []string
		out := provisionDeviceSecrets(fields, "n",
			func(f string) (string, bool, error) {
				reveals = append(reveals, f)
				return "", false, errors.New("decrypt boom")
			},
			func(fw, v string) (string, bool) { return "", true },
		)
		if out.AbortMsg != "secret+decrypt+failed" {
			t.Errorf("AbortMsg = %q, want secret+decrypt+failed", out.AbortMsg)
		}
		if len(reveals) != 1 {
			t.Errorf("reveals = %v, want to stop after the first field", reveals)
		}
	})

	t.Run("push failure aborts with the push message", func(t *testing.T) {
		out := provisionDeviceSecrets([]string{"mqtt.password"}, "n",
			func(f string) (string, bool, error) { return "mp", true, nil },
			func(fw, v string) (string, bool) { return "device+rejected+secret", false },
		)
		if out.AbortMsg != "device+rejected+secret" {
			t.Errorf("AbortMsg = %q, want device+rejected+secret", out.AbortMsg)
		}
		if len(out.Pushed) != 0 {
			t.Errorf("Pushed = %v, want none (aborted on the failing push)", out.Pushed)
		}
	})

	t.Run("all unset is a clean no-op", func(t *testing.T) {
		out := provisionDeviceSecrets(fields, "n",
			func(f string) (string, bool, error) { return "", false, nil },
			func(fw, v string) (string, bool) {
				t.Fatal("push must not be called when nothing is set")
				return "", false
			},
		)
		if out.AbortMsg != "" || len(out.Pushed) != 0 || len(out.SkippedUnset) != len(fields) {
			t.Errorf("all-unset outcome = %+v, want clean skip of every field", out)
		}
	})
}
