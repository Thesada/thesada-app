package service

import (
	"testing"
	"time"
)

func TestAbsenceDue_StaleIsDueFreshAndNeverSeenAreNot(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	if !AbsenceDue(now.Add(-16*time.Minute), now, 15*time.Minute) {
		t.Fatal("stale sample was not due")
	}
	if AbsenceDue(now.Add(-5*time.Minute), now, 15*time.Minute) {
		t.Fatal("fresh sample was due")
	}
	if AbsenceDue(time.Time{}, now, 15*time.Minute) {
		t.Fatal("never-seen was treated as absence")
	}
}

func TestAbsenceDue_NonPositiveWindowIsNotDue(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	seen := now.Add(-time.Hour)
	if AbsenceDue(seen, now, 0) || AbsenceDue(seen, now, -time.Minute) {
		t.Fatal("non-positive window marked the device absent")
	}
}

func TestAbsenceEpisode_OpensOncePerQuietStretch(t *testing.T) {
	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	seen := now.Add(-AbsenceWindow)
	if !AbsenceEpisodeOpen(seen, now, AbsenceWindow, time.Time{}) {
		t.Fatal("first quiet episode did not open")
	}
	if AbsenceEpisodeOpen(seen, now, AbsenceWindow, now.Add(-time.Minute)) {
		t.Fatal("episode already alerted was opened again")
	}
	if !AbsenceEpisodeOpen(now.Add(-20*time.Minute), now, AbsenceWindow, now.Add(-40*time.Minute)) {
		t.Fatal("new quiet stretch did not open")
	}
	if AbsenceEpisodeOpen(now.Add(-time.Minute), now, AbsenceWindow, time.Time{}) {
		t.Fatal("fresh sample opened an episode")
	}
}

func TestTrendFromNewest_MatchesOldestFirstRise(t *testing.T) {
	if !TrendFromNewest([]float64{23, 21, 20}, 2) {
		t.Fatal("newest-first rise was not rising")
	}
	if TrendFromNewest([]float64{21, 20}, 2) {
		t.Fatal("small newest-first rise was rising")
	}
}

func TestTrendRising_NeedsTheMinimumClimb(t *testing.T) {
	if !TrendRising([]float64{20, 21, 23}, 2) {
		t.Fatal("rise of 3 was not rising")
	}
	if TrendRising([]float64{20, 21}, 2) {
		t.Fatal("rise of 1 was rising")
	}
	if TrendRising([]float64{20}, 1) {
		t.Fatal("one sample was rising")
	}
}

func TestTrendRising_NegativeDeltaIsNotRising(t *testing.T) {
	if TrendRising([]float64{1, 9}, -1) {
		t.Fatal("negative minimum counted as a rise")
	}
}
