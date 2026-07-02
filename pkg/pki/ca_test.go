package pki

// Contracts for the CA signing surface and the load/parse/migrate error
// paths not exercised by encrypt_test.go. All pure crypto + filesystem, so
// they run in the default lane against a t.TempDir() CA - no refactor needed.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testCA(t *testing.T) *CA {
	t.Helper()
	ca, _, err := Bootstrap(t.TempDir(), "bootstrap-pass")
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	return ca
}

// ── SignDeviceCert ─────────────────────────────────────────────────────

func TestSignDeviceCert_SignedByCA_ClientAuthLeaf(t *testing.T) {
	ca := testCA(t)
	const cn = "thesada-acme-owb-01"

	certPEM, keyPEM, serialHex, err := ca.SignDeviceCert(cn, 24*time.Hour)
	if err != nil {
		t.Fatalf("SignDeviceCert: %v", err)
	}

	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("cert PEM did not decode to a CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse device cert: %v", err)
	}

	// Signed by our CA (this is the mTLS trust root contract).
	if err := cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("device cert not signed by CA: %v", err)
	}
	// A leaf, not a CA: a device cert must never be able to mint more certs.
	if cert.IsCA {
		t.Error("device cert has IsCA=true; must be a leaf")
	}
	// Client-auth EKU only - the cert authenticates a device to the broker,
	// it must not be usable as a server cert.
	if len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Errorf("ExtKeyUsage = %v, want [ClientAuth]", cert.ExtKeyUsage)
	}
	if cert.Subject.CommonName != cn {
		t.Errorf("CN = %q, want %q", cert.Subject.CommonName, cn)
	}
	// serialHex must be the cert's actual serial (used as the device pairing id).
	if serialHex != fmt.Sprintf("%x", cert.SerialNumber) {
		t.Errorf("serialHex %q != cert serial %x", serialHex, cert.SerialNumber)
	}

	// The returned key is a usable PKCS#8 ECDSA key matching the cert.
	kblock, _ := pem.Decode([]byte(keyPEM))
	if kblock == nil || kblock.Type != "PRIVATE KEY" {
		t.Fatalf("key PEM is not a PKCS#8 PRIVATE KEY block")
	}
	k, err := x509.ParsePKCS8PrivateKey(kblock.Bytes)
	if err != nil {
		t.Fatalf("parse device key: %v", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("device key is %T, want *ecdsa.PrivateKey", k)
	}
	if !ek.PublicKey.Equal(cert.PublicKey) {
		t.Error("returned key does not match the certificate public key")
	}
}

func TestSignDeviceCert_SerialsAreUnique(t *testing.T) {
	ca := testCA(t)
	_, _, s1, err := ca.SignDeviceCert("dev-a", time.Hour)
	if err != nil {
		t.Fatalf("sign a: %v", err)
	}
	_, _, s2, err := ca.SignDeviceCert("dev-b", time.Hour)
	if err != nil {
		t.Fatalf("sign b: %v", err)
	}
	if s1 == s2 {
		t.Errorf("two device certs share serial %q (collision risk)", s1)
	}
}

// ── CertPEMString / PlaintextKey.Error ─────────────────────────────────

func TestCertPEMString_MatchesCertPEM(t *testing.T) {
	ca := testCA(t)
	s := ca.CertPEMString()
	if s != string(ca.CertPEM) {
		t.Error("CertPEMString != CertPEM")
	}
	if block, _ := pem.Decode([]byte(s)); block == nil || block.Type != "CERTIFICATE" {
		t.Error("CertPEMString is not a CERTIFICATE PEM")
	}
}

func TestPlaintextKeyError_NamesPath(t *testing.T) {
	err := (&PlaintextKey{Path: "/var/lib/thesada/ca.key"}).Error()
	if !strings.Contains(err, "/var/lib/thesada/ca.key") {
		t.Errorf("Error() = %q, want it to name the exposed path", err)
	}
}

// ── load: SEC1 plaintext (legacy) + error branches ─────────────────────

// writeSelfSignedCA writes a matching ca.key (in the given PEM type) + ca.crt
// pair into dir and returns the key.
func writeLegacyCA(t *testing.T, dir, keyType string) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(42),
		Subject:               pkix.Name{CommonName: "legacy CA"},
		NotBefore:             now,
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("self-sign: %v", err)
	}
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", der)

	var body []byte
	switch keyType {
	case "EC PRIVATE KEY":
		body, err = x509.MarshalECPrivateKey(key)
	case "PRIVATE KEY":
		body, err = x509.MarshalPKCS8PrivateKey(key)
	}
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	writePEM(t, filepath.Join(dir, "ca.key"), keyType, body)
	return key
}

func writePEM(t *testing.T, path, typ string, der []byte) {
	t.Helper()
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestBootstrap_LoadsSEC1PlaintextWithWarning(t *testing.T) {
	dir := t.TempDir()
	key := writeLegacyCA(t, dir, "EC PRIVATE KEY")

	ca, warn, err := Bootstrap(dir, "")
	if err != nil {
		t.Fatalf("Bootstrap SEC1: %v", err)
	}
	if warn == nil {
		t.Error("plaintext SEC1 key should surface a PlaintextKey warning")
	}
	if !ca.Key.Equal(key) {
		t.Error("loaded key does not match the on-disk SEC1 key")
	}
}

func TestLoad_BadKeyPEM(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("not a pem block"), 0600); err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", []byte("x"))
	if _, _, err := Bootstrap(dir, ""); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Fatalf("err = %v, want 'no PEM block'", err)
	}
}

func TestLoad_BadCertPEM(t *testing.T) {
	dir := t.TempDir()
	writeLegacyCA(t, dir, "PRIVATE KEY") // valid key
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("garbage"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Bootstrap(dir, ""); err == nil || !strings.Contains(err.Error(), "CA cert: no PEM block") {
		t.Fatalf("err = %v, want cert 'no PEM block'", err)
	}
}

func TestLoad_EncryptedNonECDSAKeyRejected(t *testing.T) {
	dir := t.TempDir()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa gen: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("marshal rsa: %v", err)
	}
	env, err := encryptCAKey(pkcs8, "pass")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), env, 0600); err != nil {
		t.Fatal(err)
	}
	writePEM(t, filepath.Join(dir, "ca.crt"), "CERTIFICATE", []byte("x"))
	if _, _, err := Bootstrap(dir, "pass"); err == nil || !strings.Contains(err.Error(), "not ECDSA") {
		t.Fatalf("err = %v, want 'not ECDSA'", err)
	}
}

// ── EncryptKeyOnDisk / sanitizeCADir error branches ────────────────────

func TestEncryptKeyOnDisk_RejectsEmptyPassphrase(t *testing.T) {
	if err := EncryptKeyOnDisk("/tmp/whatever", ""); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v, want empty-passphrase rejection", err)
	}
}

func TestEncryptKeyOnDisk_RejectsRelativeDir(t *testing.T) {
	if err := EncryptKeyOnDisk("relative/dir", "pass"); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("err = %v, want absolute-path rejection", err)
	}
}

func TestSanitizeCADir_RejectsEmpty(t *testing.T) {
	if err := EncryptKeyOnDisk("", "pass"); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Fatalf("err = %v, want empty-dir rejection", err)
	}
}

func TestEncryptKeyOnDisk_UnsupportedPEMType(t *testing.T) {
	dir := t.TempDir()
	writePEM(t, filepath.Join(dir, "ca.key"), "CERTIFICATE", []byte("x")) // wrong block type
	if err := EncryptKeyOnDisk(dir, "pass"); err == nil || !strings.Contains(err.Error(), "unsupported PEM type") {
		t.Fatalf("err = %v, want unsupported-PEM-type", err)
	}
}

func TestEncryptKeyOnDisk_NoPEMBlock(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("plain text, no pem"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptKeyOnDisk(dir, "pass"); err == nil || !strings.Contains(err.Error(), "no PEM block") {
		t.Fatalf("err = %v, want no-PEM-block", err)
	}
}
