package service

import "testing"

func TestFirmwareSecretField(t *testing.T) {
	// The four non-wifi.password fields map 1:1 to the firmware key.
	for _, f := range []string{"mqtt.password", "telegram.bot_token", "web.password", "wifi.ap_password"} {
		got, ok := FirmwareSecretField(f, "any-ssid")
		if !ok || got != f {
			t.Errorf("FirmwareSecretField(%q) = %q,%v, want %q,true", f, got, ok, f)
		}
	}

	t.Run("wifi.password becomes per-SSID", func(t *testing.T) {
		got, ok := FirmwareSecretField("wifi.password", "HomeNet")
		if !ok || got != "wifi.password:HomeNet" {
			t.Errorf("= %q,%v, want wifi.password:HomeNet,true", got, ok)
		}
	})

	t.Run("wifi.password with no SSID is skipped", func(t *testing.T) {
		if got, ok := FirmwareSecretField("wifi.password", ""); ok || got != "" {
			t.Errorf("= %q,%v, want \"\",false (skip when SSID unknown)", got, ok)
		}
	})
}
