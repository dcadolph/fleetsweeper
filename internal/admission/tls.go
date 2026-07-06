package admission

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

// certCheckInterval throttles how often GetCertificate re-examines the
// certificate for staleness. Handshakes between checks reuse the cached cert.
const certCheckInterval = time.Minute

// selfSignedCAValidity is the lifetime of the generated CA. The CA is what
// operators patch into the ValidatingWebhookConfiguration caBundle, so it is
// long-lived; only the leaf rotates.
const selfSignedCAValidity = 10 * 365 * 24 * time.Hour

// selfSignedLeafValidity is the lifetime of each generated serving cert.
const selfSignedLeafValidity = 30 * 24 * time.Hour

// selfSignedRotateBefore is how long before leaf expiry a new leaf is issued.
const selfSignedRotateBefore = 7 * 24 * time.Hour

// CertSource supplies the admission server's serving certificate and keeps it
// fresh. File-backed certificates are reloaded from disk when the files
// change, which supports cert-manager rotating a mounted secret. Generated
// certificates are issued from an in-memory CA and reissued before expiry, so
// the caBundle handed to the apiserver stays valid for the CA's lifetime.
type CertSource struct {
	certPath string
	keyPath  string
	dnsNames []string

	mu        sync.Mutex
	cert      *tls.Certificate
	caPEM     []byte
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	notAfter  time.Time
	fileMod   time.Time
	lastCheck time.Time
}

// NewCertSource loads the file-backed keypair when both paths are set, or
// generates a CA and serving certificate covering dnsNames when either path
// is empty. The error covers unreadable files and generation failures.
func NewCertSource(certPath, keyPath string, dnsNames []string) (*CertSource, error) {
	s := &CertSource{certPath: certPath, keyPath: keyPath, dnsNames: dnsNames}
	if s.fileBacked() {
		if err := s.loadFromFiles(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err := s.generateCA(); err != nil {
		return nil, err
	}
	if err := s.issueLeaf(); err != nil {
		return nil, err
	}
	return s, nil
}

// GetCertificate implements the tls.Config hook. It refreshes the certificate
// at most once per certCheckInterval: file-backed certs reload when the files'
// modification times change, generated certs reissue when the leaf is within
// selfSignedRotateBefore of expiry. Refresh failures fall back to the cached
// certificate so a transient filesystem error does not break handshakes.
func (s *CertSource) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if now.Sub(s.lastCheck) >= certCheckInterval {
		s.lastCheck = now
		s.refreshLocked(now)
	}
	return s.cert, nil
}

// CABundle returns the PEM-encoded bundle the apiserver should trust: the
// file contents for file-backed certs, or the generated CA otherwise. Stable
// across leaf rotations.
func (s *CertSource) CABundle() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.caPEM
}

// fileBacked reports whether the source reloads from disk.
func (s *CertSource) fileBacked() bool { return s.certPath != "" && s.keyPath != "" }

// refreshLocked renews the certificate when stale. Callers must hold mu.
func (s *CertSource) refreshLocked(now time.Time) {
	if s.fileBacked() {
		mod, err := latestModTime(s.certPath, s.keyPath)
		if err != nil || !mod.After(s.fileMod) {
			return
		}
		// Reload errors keep the previous cert; the next interval retries.
		_ = s.loadFromFiles()
		return
	}
	if now.Add(selfSignedRotateBefore).Before(s.notAfter) {
		return
	}
	_ = s.issueLeaf()
}

// loadFromFiles reads the keypair and CA bundle from disk. Callers must hold
// mu or be the constructor.
func (s *CertSource) loadFromFiles() error {
	cert, err := tls.LoadX509KeyPair(s.certPath, s.keyPath)
	if err != nil {
		return fmt.Errorf("load tls keypair: %w", err)
	}
	caPEM, err := os.ReadFile(s.certPath)
	if err != nil {
		return fmt.Errorf("read ca pem: %w", err)
	}
	mod, err := latestModTime(s.certPath, s.keyPath)
	if err != nil {
		return fmt.Errorf("stat tls keypair: %w", err)
	}
	s.cert = &cert
	s.caPEM = caPEM
	s.fileMod = mod
	return nil
}

// generateCA creates the long-lived signing CA used for generated leaves.
func (s *CertSource) generateCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate ca key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return err
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "fleetsweeper-admission-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(selfSignedCAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create ca cert: %w", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parse ca cert: %w", err)
	}
	s.caCert = caCert
	s.caKey = key
	s.caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return nil
}

// issueLeaf signs a fresh serving certificate with the CA. Callers must hold
// mu or be the constructor.
func (s *CertSource) issueLeaf() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}
	serial, err := newSerial()
	if err != nil {
		return err
	}
	notAfter := time.Now().Add(selfSignedLeafValidity)
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "fleetsweeper-admission"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     s.dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, s.caCert, &key.PublicKey, s.caKey)
	if err != nil {
		return fmt.Errorf("create cert: %w", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("assemble keypair: %w", err)
	}
	s.cert = &cert
	s.notAfter = notAfter
	return nil
}

// newSerial returns a random 128-bit certificate serial number.
func newSerial() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("serial: %w", err)
	}
	return serial, nil
}

// latestModTime returns the newest modification time across the given paths.
func latestModTime(paths ...string) (time.Time, error) {
	var latest time.Time
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return time.Time{}, err
		}
		if info.ModTime().After(latest) {
			latest = info.ModTime()
		}
	}
	return latest, nil
}
