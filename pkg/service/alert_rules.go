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
