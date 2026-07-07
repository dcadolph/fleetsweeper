// Package testcerts generates self-signed X.509 certificates for tests that
// exercise certificate parsing and expiry logic. It exists so certificate
// generation is written once and shared by every scanner test that needs a
// PEM bundle with a controlled expiry.
package testcerts

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

// PEMWithExpiry returns a PEM-encoded self-signed certificate whose subject
// common name is cn and whose NotAfter is notAfter. The key is discarded; the
// certificate is only for parsing, never for a live handshake.
func PEMWithExpiry(cn string, notAfter time.Time) ([]byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notAfter.Add(-365 * 24 * time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}
