package v1

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"thesada.app/app/pkg/config"
)

func newEnrollTestServer() *Server {
	return &Server{mux: http.NewServeMux(), enroll: newEnrollLimiters()}
}

// A well-formed device key: 32 bytes of lowercase hex. The gate only checks
// the shape, so the bytes need not be on the curve.
const enrollTestPubkey = "abababababababababababababababababababababababababababababababab"

// enrollTestPubkeyN returns a distinct well-formed key per index, for tests
// that need several enrollments under one device_id. Distinct per i, not
// merely per i mod 16 - a repeating key makes a per-key limit test pass on
// some other limiter.
func enrollTestPubkeyN(i int) string {
	return fmt.Sprintf("%064x", i)
}

// --- enrollClientIP ---------------------------------------------------------

func TestEnrollClientIPUsesRemoteAddrWhenPeerUntrusted(t *testing.T) {
	s := newEnrollTestServer()
	r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	if got := s.enrollClientIP(r); got != "203.0.113.7" {
		t.Fatalf("want 203.0.113.7, got %q", got)
	}
}

// An untrusted peer must not be able to choose its own rate-limit bucket.
func TestEnrollClientIPIgnoresForwardedFromUntrustedPeer(t *testing.T) {
	s := newEnrollTestServer()
	r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	if got := s.enrollClientIP(r); got != "203.0.113.7" {
		t.Fatalf("forwarded header from untrusted peer must be ignored, got %q", got)
	}
}

// Behind the real deployment's reverse proxy every device shares one
// RemoteAddr. Without honouring the forwarded header from a TRUSTED peer, the
// per-IP limit becomes one global bucket for the whole fleet and one polling
// device rate-limits every other device.
func TestEnrollClientIPHonoursForwardedFromTrustedProxy(t *testing.T) {
	s := newEnrollTestServer()
	_, proxyNet, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatalf("cidr: %v", err)
	}
	s.cfg = &config.Config{TrustedProxies: []*net.IPNet{proxyNet}}

	r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
	r.RemoteAddr = "192.0.2.10:443"
	r.Header.Set("X-Forwarded-For", "198.51.100.9")
	if got := s.enrollClientIP(r); got != "198.51.100.9" {
		t.Fatalf("trusted proxy forwarded IP must be used, got %q", got)
	}
}

// A spoofed prefix ahead of the real client must not become the key.
func TestEnrollClientIPSkipsSpoofedPrefix(t *testing.T) {
	s := newEnrollTestServer()
	_, proxyNet, _ := net.ParseCIDR("192.0.2.0/24")
	s.cfg = &config.Config{TrustedProxies: []*net.IPNet{proxyNet}}

	r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
	r.RemoteAddr = "192.0.2.10:443"
	r.Header.Set("X-Forwarded-For", "junk-not-an-ip, 198.51.100.9")
	if got := s.enrollClientIP(r); got != "198.51.100.9" {
		t.Fatalf("want the rightmost untrusted parseable IP, got %q", got)
	}
}

// --- rejection shape --------------------------------------------------------

// Every refusal on this surface must look the same. A caller must not be able
// to tell an unknown device from a wrong token from a stale challenge.
func TestEnrollRejectIsUniform(t *testing.T) {
	w := httptest.NewRecorder()
	enrollReject(w)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["error"] != "enrollment refused" {
		t.Fatalf("unexpected body %v", body)
	}
	if len(body) != 1 {
		t.Fatalf("response must carry no extra detail, got %v", body)
	}
}

// Malformed input is refused with the same shape, and must not reach the
// service layer (this server has no services wired, so a call would panic).
func TestEnrollAnnounceRejectsMalformedBody(t *testing.T) {
	s := newEnrollTestServer()
	r := httptest.NewRequest(http.MethodPost, "/devices/enroll", strings.NewReader("{not json"))
	r.RemoteAddr = "203.0.113.7:1"
	w := httptest.NewRecorder()
	s.handleEnrollAnnounce(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

// An oversized body must be refused rather than buffered. Without the
// MaxBytesReader an unauthenticated caller sets the memory budget.
func TestEnrollAnnounceRejectsOversizedBody(t *testing.T) {
	s := newEnrollTestServer()
	huge := `{"device_id":"thesada-aabbccddeeff","pubkey":"` + strings.Repeat("a", 8192) + `"}`
	r := httptest.NewRequest(http.MethodPost, "/devices/enroll", strings.NewReader(huge))
	r.RemoteAddr = "203.0.113.7:1"
	w := httptest.NewRecorder()
	s.handleEnrollAnnounce(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
}

// --- rate limiting ----------------------------------------------------------

// Per-IP: one host walking many device ids still hits a ceiling.
func TestEnrollGateRateLimitsPerIP(t *testing.T) {
	s := newEnrollTestServer()
	r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
	r.RemoteAddr = "203.0.113.7:1"

	for i := 0; i < enrollPerIPMax; i++ {
		w := httptest.NewRecorder()
		// A distinct device id each time, so only the IP limiter can trip.
		if !s.enrollGate(w, r, "thesada-"+pad(i), enrollTestPubkey) {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	w := httptest.NewRecorder()
	if s.enrollGate(w, r, "thesada-ffffffffffff", enrollTestPubkey) {
		t.Fatal("per-IP limit must trip after the cap")
	}
	assertUniformRefusal(t, w)
}

// Per-enrollment: many hosts hammering one enrollment still hit a ceiling.
func TestEnrollGateRateLimitsPerEnrollment(t *testing.T) {
	s := newEnrollTestServer()
	const dev = "thesada-aabbccddeeff"

	for i := 0; i < enrollPerPairMax; i++ {
		r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
		r.RemoteAddr = testIP(i)
		w := httptest.NewRecorder()
		if !s.enrollGate(w, r, dev, enrollTestPubkey) {
			t.Fatalf("request %d should be allowed", i)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
	r.RemoteAddr = "198.51.100.1:1"
	w := httptest.NewRecorder()
	if s.enrollGate(w, r, dev, enrollTestPubkey) {
		t.Fatal("per-enrollment limit must trip even from a fresh IP")
	}
	assertUniformRefusal(t, w)
}

// The per-enrollment bucket is keyed on (device_id, pubkey), so a caller who
// guessed a device_id cannot spend the budget of the device that owns it. With
// the bucket keyed on device_id alone, one guess starved a real unit for the
// rest of the hour and every certificate poll paid into the same bucket.
func TestEnrollGateBudgetIsPerEnrollmentNotPerDeviceID(t *testing.T) {
	s := newEnrollTestServer()
	const dev = "thesada-aabbccddeeff"
	attacker := enrollTestPubkeyN(1)

	for i := 0; i < enrollPerPairMax; i++ {
		r := httptest.NewRequest(http.MethodPost, "/devices/enroll/cert", nil)
		r.RemoteAddr = testIP(i)
		w := httptest.NewRecorder()
		if !s.enrollGate(w, r, dev, attacker) {
			t.Fatalf("attacker request %d should be allowed", i)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/devices/enroll/cert", nil)
	r.RemoteAddr = "198.51.100.1:1"
	w := httptest.NewRecorder()
	if s.enrollGate(w, r, dev, attacker) {
		t.Fatal("the attacker must have exhausted its own bucket")
	}
	// The real device, same id, its own key: untouched.
	r = httptest.NewRequest(http.MethodPost, "/devices/enroll/cert", nil)
	r.RemoteAddr = "198.51.100.2:1"
	w = httptest.NewRecorder()
	if !s.enrollGate(w, r, dev, enrollTestPubkey) {
		t.Fatal("a spent bucket for one keypair must not spend another's")
	}
}

// The per-device_id cap survives, on announce alone: it bounds how many rows
// one guessable id can occupy. Verify, cert and ack do not spend it, so a
// device that has announced keeps working while a flood is in progress.
func TestEnrollAnnounceGateCapsRowsPerDeviceID(t *testing.T) {
	s := newEnrollTestServer()
	const dev = "thesada-aabbccddeeff"

	for i := 0; i < enrollPerIDMax; i++ {
		r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
		r.RemoteAddr = testIP(i)
		w := httptest.NewRecorder()
		if !s.enrollAnnounceGate(w, r, dev, enrollTestPubkeyN(i)) {
			t.Fatalf("announce %d should be allowed", i)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
	r.RemoteAddr = "198.51.100.1:1"
	w := httptest.NewRecorder()
	if s.enrollAnnounceGate(w, r, dev, enrollTestPubkeyN(enrollPerIDMax)) {
		t.Fatal("announce must stop creating rows once the per-id cap is spent")
	}
	assertUniformRefusal(t, w)

	// The non-announce endpoints keep working for a device that already has a
	// row, because they never touch the per-id bucket.
	r = httptest.NewRequest(http.MethodPost, "/devices/enroll/cert", nil)
	r.RemoteAddr = "198.51.100.2:1"
	w = httptest.NewRecorder()
	if !s.enrollGate(w, r, dev, enrollTestPubkey) {
		t.Fatal("a spent per-id bucket must not gate cert polling")
	}
}

// A rate-limited caller must be indistinguishable from every other refusal.
// The per-device bucket is keyed on device_id, so a 429 would report that some
// other party is enrolling that id right now - the oracle the ledger forbids.
func assertUniformRefusal(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body) != 1 || body["error"] != "enrollment refused" {
		t.Fatalf("refusal body must be the uniform one, got %v", body)
	}
}

// The limiters key maps on body fields from an unauthenticated caller. Without
// a shape check first, map growth is chosen by whoever is talking to the
// endpoint - one request per distinct string, forever.
func TestEnrollGateRefusesMalformedDeviceID(t *testing.T) {
	for _, bad := range []string{
		"", "thesada-", "thesada-nothex00000a", "thesada-aabbccddeefff",
		"node-1", "thesada-AABBCCDDEEFF", strings.Repeat("x", 4096),
	} {
		s := newEnrollTestServer()
		r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
		r.RemoteAddr = "203.0.113.7:1"
		w := httptest.NewRecorder()
		if s.enrollGate(w, r, bad, enrollTestPubkey) {
			t.Fatalf("%q must not pass the gate", bad)
		}
		assertUniformRefusal(t, w)
	}
}

// The pubkey is half the rate-limit key, so it is shape-checked before it is
// used as one. Without that an unauthenticated caller picks how much memory
// the limiter map holds, one request per distinct string.
func TestEnrollGateRefusesMalformedPubkey(t *testing.T) {
	for _, bad := range []string{
		"", "ab", strings.ToUpper(enrollTestPubkey), enrollTestPubkey + "ab",
		strings.Repeat("z", 64), strings.Repeat("x", 4096),
	} {
		s := newEnrollTestServer()
		r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
		r.RemoteAddr = "203.0.113.7:1"
		w := httptest.NewRecorder()
		if s.enrollGate(w, r, "thesada-aabbccddeeff", bad) {
			t.Fatalf("pubkey %q must not pass the gate", bad)
		}
		assertUniformRefusal(t, w)
	}
}

// The per-IP token is spent before the shape check, so a flood of garbage ids
// still costs the sender its own budget rather than being free.
func TestEnrollGateSpendsIPBudgetOnMalformedDeviceID(t *testing.T) {
	s := newEnrollTestServer()
	r := httptest.NewRequest(http.MethodPost, "/devices/enroll", nil)
	r.RemoteAddr = "203.0.113.7:1"
	for i := 0; i < enrollPerIPMax; i++ {
		w := httptest.NewRecorder()
		if s.enrollGate(w, r, "junk", enrollTestPubkey) {
			t.Fatal("malformed id must never pass")
		}
	}
	// The budget is gone, so even a well-formed id is now refused.
	w := httptest.NewRecorder()
	if s.enrollGate(w, r, "thesada-aabbccddeeff", enrollTestPubkey) {
		t.Fatal("per-IP budget must have been spent by the malformed requests")
	}
	assertUniformRefusal(t, w)
}

// A nil CA is a server misconfiguration, and it used to answer 503 before any
// gate ran - the one reply this surface handed out for free.
func TestEnrollCertWithoutCAIsUniformlyRefused(t *testing.T) {
	s := newEnrollTestServer()
	body := `{"device_id":"thesada-aabbccddeeff","pubkey":"` + enrollTestPubkey + `","claim_token":"t"}`
	r := httptest.NewRequest(http.MethodPost, "/devices/enroll/cert", strings.NewReader(body))
	r.RemoteAddr = "203.0.113.7:1"
	w := httptest.NewRecorder()
	s.handleEnrollCert(w, r)
	assertUniformRefusal(t, w)
}

// pad is the 12-hex-digit tail of a device id, distinct per index.
func pad(i int) string {
	return fmt.Sprintf("%012x", i)
}

// testIP is a distinct, parseable client address per index. Zero-padded octets
// ("203.0.113.007") are not valid IPv4: net.ParseIP rejects them, enrollClientIP
// falls through to its RemoteAddr branch, and the test never exercises the
// parsed-IP path it means to.
func testIP(i int) string {
	return fmt.Sprintf("203.0.%d.%d:1", 113+i/254, 1+i%254)
}
