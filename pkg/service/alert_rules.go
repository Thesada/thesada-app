package service

import "time"

// AbsenceWindow matches the offline badge. A paired device quiet longer than
// this opens one absence episode.
const AbsenceWindow = 15 * time.Minute

// AbsenceDue reports whether lastSeen is older than window.
// A zero lastSeen or a non-positive window is not due, so a bad window cannot mark every device absent.
// in: lastSeen, now, window. out: true when the stretch is due.
func AbsenceDue(lastSeen, now time.Time, window time.Duration) bool {
	if lastSeen.IsZero() || window <= 0 {
		return false
	}
	return now.Sub(lastSeen) >= window
}

// AbsenceEpisodeOpen reports a quiet stretch that has not already produced an alert.
// in: lastSeen, now, window, last absence time. out: true when a new alert should be raised.
func AbsenceEpisodeOpen(lastSeen, now time.Time, window time.Duration, lastAbsence time.Time) bool {
	if !AbsenceDue(lastSeen, now, window) {
		return false
	}
	if lastAbsence.IsZero() {
		return true
	}
	return lastAbsence.Before(lastSeen)
}

// TrendRising reports a climb of at least minDelta from the first sample to the last.
// A negative minDelta is not a rise. The caller supplies the threshold.
// in: oldest-first samples, minimum rise. out: true when the rise is large enough.
func TrendRising(samples []float64, minDelta float64) bool {
	if len(samples) < 2 || minDelta < 0 {
		return false
	}
	return samples[len(samples)-1]-samples[0] >= minDelta
}

// TrendFromNewest is TrendRising for samples stored newest-first.
// in: newest-first samples, minimum rise. out: true when the rise is large enough.
func TrendFromNewest(newestFirst []float64, minDelta float64) bool {
	chrono := make([]float64, 0, len(newestFirst))
	for i := len(newestFirst) - 1; i >= 0; i-- {
		chrono = append(chrono, newestFirst[i])
	}
	return TrendRising(chrono, minDelta)
}
