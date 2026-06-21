// Package pki manages the thesada-app internal CA for per-device mTLS.
// On first boot, generates an ECDSA P-256 CA keypair + self-signed cert.
// On subsequent boots, loads the existing CA from disk. Signs device client
// certs during the pairing flow.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// CA holds the loaded CA certificate and private key.
type CA struct {
	Cert    *x509.Certificate
	CertPEM []byte
	Key     *ecdsa.PrivateKey
}

// PlaintextKey indicates that the CA key on disk is unencrypted PEM and
// no passphrase was supplied. The Bootstrap caller surfaces this as a
// startup warning so operators see exactly which file is exposed and
// what env var would lock it down. Not an error: the legacy plaintext
// layout has to keep working for existing deployments.
type PlaintextKey struct {
	Path string
}

func (e *PlaintextKey) Error() string {
	return "CA private key plaintext at " + e.Path
}

// ErrEncryptedKeyNoPassphrase is returned when the on-disk CA key is in
// the encrypted envelope format but Bootstrap was called with no
// passphrase. The operator dropped a sealed key in place but forgot to
// set THESADA_CA_KEY_PASSPHRASE - fail loud rather than guess.
var ErrEncryptedKeyNoPassphrase = errors.New("CA key on disk is encrypted but THESADA_CA_KEY_PASSPHRASE is empty")

// Bootstrap loads or creates the CA in the given directory. If ca.key
// and ca.crt exist, they are loaded - encrypted via THESADA_CA_KEY_
// PASSPHRASE when set, plaintext PEM otherwise (legacy). On first boot
// a new ECDSA P-256 keypair and 10-year self-signed cert are generated;
// if passphrase is non-empty the key is written as an encrypted
// envelope, else plaintext PEM (legacy).
//
// When a plaintext key is loaded without passphrase, the returned
// warning is a *PlaintextKey describing the file path - non-fatal,
// caller logs it and proceeds. When an encrypted key is loaded without
// passphrase, an error is returned (ErrEncryptedKeyNoPassphrase) and
// Bootstrap fails: this is recoverable user error, not a degraded mode.
// in: directory path, passphrase ("" disables encryption + warn-on-load).
// out: *CA, *PlaintextKey warning (nil unless the on-disk key is plaintext), fatal error.
func Bootstrap(dir, passphrase string) (*CA, *PlaintextKey, error) {
	keyPath := filepath.Join(dir, "ca.key")
	certPath := filepath.Join(dir, "ca.crt")

	if fileExists(keyPath) && fileExists(certPath) {
		ca, warn, err := load(keyPath, certPath, passphrase)
		return ca, warn, err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, fmt.Errorf("create CA dir: %w", err)
	}

	ca, warn, err := generate(keyPath, certPath, passphrase)
	return ca, warn, err
}

// SignDeviceCert generates an ECDSA P-256 keypair for a device and signs
// a client certificate with the CA. The private key is returned but NOT
// stored server-side - it is pushed to the device and then discarded.
// in: CA, common name (e.g. "thesada-tenant-device-kind"), validity duration.
// out: cert PEM, key PEM, serial hex string, error.
func (ca *CA) SignDeviceCert(cn string, validity time.Duration) (certPEM, keyPEM, serialHex string, err error) {
	// Generate device keypair
	deviceKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", "", fmt.Errorf("generate device key: %w", err)
	}

	// Random serial number (128-bit)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", "", fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"thesada"},
		},
		NotBefore: now,
		NotAfter:  now.Add(validity),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, ca.Cert, &deviceKey.PublicKey, ca.Key)
	if err != nil {
		return "", "", "", fmt.Errorf("sign cert: %w", err)
	}

	certPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	// PKCS#8 ("PRIVATE KEY") instead of SEC1 ("EC PRIVATE KEY"). Same key
	// material, wider-compat envelope. Some cellular modem firmware
	// (SIM7080G fw 1951B17 observed) rejects SEC1 in AT+CSSLCFG="CONVERT"
	// client-cert path; PKCS#8 is the format the modem stack expects.
	// WiFi-side mbedtls accepts both, so the swap only helps the cellular
	// path. Future device certs land as PKCS#8 from issue.
	keyDER, err := x509.MarshalPKCS8PrivateKey(deviceKey)
	if err != nil {
		return "", "", "", fmt.Errorf("marshal key: %w", err)
	}
	keyPEMBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return string(certPEMBytes), string(keyPEMBytes), fmt.Sprintf("%x", serial), nil
}

// CertPEMString returns the CA certificate as a PEM string for download
// or display. in: none. out: PEM string.
func (ca *CA) CertPEMString() string {
	return string(ca.CertPEM)
}

// generate creates a new CA keypair + 10-year self-signed cert. The
// cert always lands plaintext (it is meant to be distributed); the
// private key lands encrypted when passphrase is non-empty, else
// plaintext PEM with a *PlaintextKey warning returned to the caller.
// in: key path, cert path, passphrase ("" -> legacy plaintext).
// out: *CA, *PlaintextKey warning (nil unless the on-disk key is plaintext), fatal error.
func generate(keyPath, certPath, passphrase string) (*CA, *PlaintextKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate CA serial: %w", err)
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "thesada Device CA",
			Organization: []string{"thesada"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("self-sign CA cert: %w", err)
	}

	// Marshal key as PKCS#8 so encrypted + plaintext paths share the
	// same on-the-wire format and a future swap of EC P-256 for Ed25519
	// does not change the envelope shape. The old SEC1 ("EC PRIVATE
	// KEY") PEM type is gone for new keys; load() still accepts it.
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal CA key: %w", err)
	}

	var warn *PlaintextKey
	if passphrase != "" {
		envelope, err := encryptCAKey(keyDER, passphrase)
		if err != nil {
			return nil, nil, fmt.Errorf("encrypt CA key: %w", err)
		}
		if err := os.WriteFile(keyPath, envelope, 0600); err != nil {
			return nil, nil, fmt.Errorf("write encrypted CA key: %w", err)
		}
	} else {
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
		if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
			return nil, nil, fmt.Errorf("write CA key: %w", err)
		}
		warn = &PlaintextKey{Path: keyPath}
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return nil, nil, fmt.Errorf("write CA cert: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	return &CA{Cert: cert, CertPEM: certPEM, Key: key}, warn, nil
}

// load reads an existing CA keypair from disk. The key file may be an
// encrypted envelope (THESADA-CAKEY-V1 magic) or a plaintext PEM block
// (legacy layout). When the file is plaintext PEM the caller gets a
// *PlaintextKey warning so the operator sees what is exposed.
// in: key path, cert path, passphrase ("" -> plaintext-only).
// out: *CA, *PlaintextKey warning (nil unless the on-disk key is plaintext), fatal error.
func load(keyPath, certPath, passphrase string) (*CA, *PlaintextKey, error) {
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA key: %w", err)
	}

	var (
		key  *ecdsa.PrivateKey
		warn *PlaintextKey
	)
	if isEncryptedEnvelope(raw) {
		if passphrase == "" {
			return nil, nil, ErrEncryptedKeyNoPassphrase
		}
		pt, err := decryptCAKey(raw, passphrase)
		if err != nil {
			return nil, nil, fmt.Errorf("decrypt CA key: %w", err)
		}
		k, err := parseECDSAPrivateKey(pt, true)
		if err != nil {
			return nil, nil, fmt.Errorf("parse decrypted CA key: %w", err)
		}
		key = k
	} else {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, nil, errors.New("CA key: no PEM block found")
		}
		k, err := parseECDSAPrivateKey(block.Bytes, block.Type == "PRIVATE KEY")
		if err != nil {
			return nil, nil, fmt.Errorf("parse CA key: %w", err)
		}
		key = k
		warn = &PlaintextKey{Path: keyPath}
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, nil, fmt.Errorf("read CA cert: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, nil, errors.New("CA cert: no PEM block found")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse CA cert: %w", err)
	}

	return &CA{Cert: cert, CertPEM: certPEM, Key: key}, warn, nil
}

// parseECDSAPrivateKey decodes either a PKCS#8 ("PRIVATE KEY") or a SEC1
// ("EC PRIVATE KEY") body to an *ecdsa.PrivateKey. PKCS#8 is the format
// new code writes (encrypted envelope + new plaintext bootstraps);
// SEC1 stays accepted so existing pre-0020 deployments load without a
// migration step.
// in: DER bytes, pkcs8 flag (true = PKCS#8 envelope, false = SEC1).
// out: *ecdsa.PrivateKey, error.
func parseECDSAPrivateKey(der []byte, pkcs8 bool) (*ecdsa.PrivateKey, error) {
	if pkcs8 {
		k, err := x509.ParsePKCS8PrivateKey(der)
		if err != nil {
			return nil, err
		}
		ek, ok := k.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.New("CA key: PKCS#8 envelope is not ECDSA")
		}
		return ek, nil
	}
	return x509.ParseECPrivateKey(der)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
