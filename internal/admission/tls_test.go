package admission

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestCertSourceGenerated verifies a generated leaf chains to the CA bundle
// and covers the requested SANs.
func TestCertSourceGenerated(t *testing.T) {
	t.Parallel()
	src, err := NewCertSource("", "", []string{"fleetsweeper.fleet.svc"})
	if err != nil {
		t.Fatalf("NewCertSource: %v", err)
	}
	cert, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(src.CABundle()) {
		t.Fatal("CABundle: no parsable certificates")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "fleetsweeper.fleet.svc",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not verify against CA bundle: %v", err)
	}
	if leaf.IsCA {
		t.Error("leaf must not be a CA")
	}
}

// TestCertSourceRotatesLeaf verifies a leaf close to expiry is reissued on the
// next handshake and the CA bundle is unchanged.
func TestCertSourceRotatesLeaf(t *testing.T) {
	t.Parallel()
	src, err := NewCertSource("", "", []string{"fleetsweeper.fleet.svc"})
	if err != nil {
		t.Fatalf("NewCertSource: %v", err)
	}
	before, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	caBefore := string(src.CABundle())

	// Force the leaf into the rotation window and expire the check throttle.
	src.mu.Lock()
	src.notAfter = time.Now().Add(time.Hour)
	src.lastCheck = time.Time{}
	src.mu.Unlock()

	after, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate after rotation: %v", err)
	}
	if string(before.Certificate[0]) == string(after.Certificate[0]) {
		t.Error("leaf was not reissued inside the rotation window")
	}
	if caBefore != string(src.CABundle()) {
		t.Error("CA bundle changed across leaf rotation")
	}
	leaf, err := x509.ParseCertificate(after.Certificate[0])
	if err != nil {
		t.Fatalf("parse rotated leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(src.CABundle())
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("rotated leaf does not verify against CA bundle: %v", err)
	}
}

// TestCertSourceFileReload verifies file-backed certs reload when the files
// change on disk.
func TestCertSourceFileReload(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	certPath := filepath.Join(dir, "tls.crt")
	keyPath := filepath.Join(dir, "tls.key")

	writeKeypair(t, certPath, keyPath, "first.example.com")
	src, err := NewCertSource(certPath, keyPath, nil)
	if err != nil {
		t.Fatalf("NewCertSource: %v", err)
	}
	before, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}

	writeKeypair(t, certPath, keyPath, "second.example.com")
	// Push the mtime clearly past the recorded one and expire the throttle.
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(certPath, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	src.mu.Lock()
	src.lastCheck = time.Time{}
	src.mu.Unlock()

	after, err := src.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate after reload: %v", err)
	}
	if string(before.Certificate[0]) == string(after.Certificate[0]) {
		t.Error("file-backed cert was not reloaded after files changed")
	}
	leaf, err := x509.ParseCertificate(after.Certificate[0])
	if err != nil {
		t.Fatalf("parse reloaded leaf: %v", err)
	}
	if len(leaf.DNSNames) == 0 || leaf.DNSNames[0] != "second.example.com" {
		t.Errorf("reloaded cert DNS names = %v, want [second.example.com]", leaf.DNSNames)
	}
}

// writeKeypair writes a fresh self-signed keypair covering dnsName to the
// given paths.
func writeKeypair(t *testing.T, certPath, keyPath, dnsName string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := newSerial()
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: dnsName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{dnsName},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
}
