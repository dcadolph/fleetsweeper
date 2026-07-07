package certs

import (
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/testcerts"
)

// FuzzParsePEM asserts parsePEM never panics on arbitrary bytes and that every
// certificate it returns is a valid, non-nil value the scanner can read fields
// from. parsePEM is deliberately forgiving: undecodable input yields nil and a
// single malformed block is skipped, so the only invariants are crash-safety
// and validity of whatever certificates it does return.
func FuzzParsePEM(f *testing.F) {
	// A real, parseable certificate seeds the corpus so the fuzzer mutates
	// valid DER rather than only rejecting garbage at the PEM boundary.
	valid, err := testcerts.PEMWithExpiry("fuzz.example", time.Now().Add(365*24*time.Hour))
	if err != nil {
		f.Fatalf("seed cert: %v", err)
	}
	seeds := [][]byte{
		nil,
		[]byte(""),
		[]byte("not pem at all"),
		[]byte("-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n"),
		{0x00, 0x01, 0x02, 0xff},
		valid,
		append(append([]byte{}, valid...), valid...),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, c := range parsePEM(data) {
			if c == nil {
				t.Fatal("parsePEM returned a nil certificate in its result slice")
			}
			// Mirror the field accesses NewScanner performs on each cert so a
			// panic in either would surface here. The derived day count is an
			// int and therefore always finite.
			_ = c.Subject.CommonName
			_ = int(time.Until(c.NotAfter).Hours() / 24)
		}
	})
}
