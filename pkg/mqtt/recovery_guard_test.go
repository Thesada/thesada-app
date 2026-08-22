package mqtt

import (
	"errors"
	"testing"
)

// The recovery sequence wipes the device's only cert before handing it to the
// shared fallback credential. If that credential is disabled, the device
// reboots into a broker that refuses it and needs serial recovery.
func TestRecoveryPathUsableRejectsDisabledFallback(t *testing.T) {
	if RecoveryPathUsable(false, nil) {
		t.Fatal("a disabled fallback credential must block the recovery path")
	}
}

// An unreachable broker is not evidence the credential works. Guessing
// "enabled" here strands the device just as surely as a disabled one.
func TestRecoveryPathUsableRejectsProbeError(t *testing.T) {
	if RecoveryPathUsable(true, errors.New("broker unreachable")) {
		t.Fatal("a probe error must block the recovery path even when enabled is true")
	}
	if RecoveryPathUsable(false, errors.New("broker unreachable")) {
		t.Fatal("a probe error must block the recovery path")
	}
}

func TestRecoveryPathUsableAllowsEnabledFallback(t *testing.T) {
	if !RecoveryPathUsable(true, nil) {
		t.Fatal("an enabled fallback credential must permit the recovery path")
	}
}
