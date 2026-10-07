package service

import "testing"

func TestQuotaFullRefusesAtTheCapAndIgnoresANonPositiveMax(t *testing.T) {
	if quotaFull(24, 25) || !quotaFull(25, 25) || !quotaFull(26, 25) {
		t.Fatal("count against a positive cap")
	}
	if quotaFull(100, 0) || quotaFull(100, -1) {
		t.Fatal("non-positive cap is off")
	}
}
