package service

import "testing"

func TestFirmwareSecretField(t *testing.T) {
	// The four scalars map 1:1 to the firmware key.
	for _, f := range ScalarSecretFields {
		got, ok := FirmwareSecretField(f, "any-ssid")
		if !ok || got != f {
			t.Errorf("FirmwareSecretField(%q) = %q,%v, want %q,true", f, got, ok, f)
		}
	}

	t.Run("per-SSID wifi field passes through unchanged", func(t *testing.T) {
		got, ok := FirmwareSecretField("wifi.password:HomeNet", "")
		if !ok || got != "wifi.password:HomeNet" {
			t.Errorf("= %q,%v, want wifi.password:HomeNet,true (SSID already in key)", got, ok)
		}
	})

	t.Run("legacy bare wifi.password becomes per-SSID via primary SSID", func(t *testing.T) {
		got, ok := FirmwareSecretField("wifi.password", "HomeNet")
		if !ok || got != "wifi.password:HomeNet" {
			t.Errorf("= %q,%v, want wifi.password:HomeNet,true", got, ok)
		}
	})

	t.Run("legacy wifi.password with no SSID is skipped", func(t *testing.T) {
		if got, ok := FirmwareSecretField("wifi.password", ""); ok || got != "" {
			t.Errorf("= %q,%v, want \"\",false (skip when SSID unknown)", got, ok)
		}
	})
}

func TestWifiSecretFieldAndValidation(t *testing.T) {
	if got := WifiSecretField("HomeNet"); got != "wifi.password:HomeNet" {
		t.Errorf("WifiSecretField = %q, want wifi.password:HomeNet", got)
	}
	if got := WifiSecretField(""); got != "" {
		t.Errorf("WifiSecretField(\"\") = %q, want empty", got)
	}

	valid := []string{"mqtt.password", "web.password", "wifi.ap_password",
		"wifi.password", "wifi.password:HomeNet", "wifi.password:has spaces"}
	for _, f := range valid {
		if !validSecretField(f) {
			t.Errorf("validSecretField(%q) = false, want true", f)
		}
	}
	invalid := []string{"", "wifi.password:", "mqtt.broker", "wifi.ssid", "wifi.networks"}
	for _, f := range invalid {
		if validSecretField(f) {
			t.Errorf("validSecretField(%q) = true, want false", f)
		}
	}
}
