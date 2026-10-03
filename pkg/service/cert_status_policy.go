package service

import (
	"strconv"
	"strings"
	"time"
)

// Cert-status decision rules. The firmware wipes a stored cert only when
// this app answers revoked for that exact serial. Every other answer,
// including a database error, must leave the cert in place.

// EnrollStatusDomain is the first line of the signed status statement.
// The firmware builds the same bytes; a drift here refuses every device.
const EnrollStatusDomain = "thesada-enroll-status"

// EnrollStatusSkew is how far a signed timestamp may sit from now.
// Same bound as the claim challenge: long enough for one round trip,
// short enough that a captured request dies.
const EnrollStatusSkew = 5 * time.Minute

// Answers the status endpoint returns. The firmware treats only revoked
// as a wipe, and logs these words as fixed tokens.
const (
	EnrollStatusActive  = "active"
	EnrollStatusRevoked = "revoked"
	EnrollStatusUnknown = "unknown"
)

// enrollSerialMaxLen matches the firmware cap: 40 hex chars plus a NUL.
const enrollSerialMaxLen = 40

// CertStatusRow is the certificate row a status lookup found, if any.
type CertStatusRow struct {
	Revoked   bool
	Status    string
	PubkeyHex string
	DeviceID  string
}

// CertSerialTombstone is a serial remembered after its device row was deleted.
type CertSerialTombstone struct {
	DeviceID  string
	PubkeyHex string
}

// CanonicalCertSerial is the form the firmware signs and the form we store:
// lowercase hex, no leading zeros except the value "0".
// in: raw serial. out: canonical serial, false when it is not that shape.
func CanonicalCertSerial(in string) (string, bool) {
	if in == "" || in != strings.ToLower(in) {
		return "", false
	}
	for _, c := range in {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	s := strings.TrimLeft(in, "0")
	if s == "" {
		s = "0"
	}
	if len(s) > enrollSerialMaxLen {
		return "", false
	}
	return s, true
}

// EnrollStatusMessage is the exact byte string the device signs.
// in: device id, canonical serial, unix seconds. out: statement.
func EnrollStatusMessage(deviceID, serial string, ts int64) string {
	return EnrollStatusDomain + "\n" + deviceID + "\n" + serial + "\n" + strconv.FormatInt(ts, 10)
}

// EnrollStatusFresh reports whether ts is within EnrollStatusSkew of now.
// in: now, unix seconds from the request. out: true when the window holds.
func EnrollStatusFresh(now time.Time, ts int64) bool {
	delta := now.Sub(time.Unix(ts, 0))
	if delta < 0 {
		delta = -delta
	}
	return delta <= EnrollStatusSkew
}

// CertRevocationAnswer picks the status word for one signed request.
// A pubkey or device id that does not match the stored identity is unknown,
// not a refusal: the caller already proved a key, and unknown keeps the cert.
// in: device id, pubkey, cert row (nil if none), tombstone (nil if none).
// out: active, revoked, or unknown.
func CertRevocationAnswer(deviceID, pubkey string, row *CertStatusRow, tomb *CertSerialTombstone) string {
	if row != nil {
		if row.PubkeyHex == "" || row.PubkeyHex != pubkey || row.DeviceID != deviceID {
			return EnrollStatusUnknown
		}
		if row.Revoked {
			return EnrollStatusRevoked
		}
		if row.Status == CertStatusActive {
			return EnrollStatusActive
		}
		return EnrollStatusUnknown
	}
	if tomb != nil && tomb.PubkeyHex == pubkey && tomb.DeviceID == deviceID {
		return EnrollStatusRevoked
	}
	return EnrollStatusUnknown
}
