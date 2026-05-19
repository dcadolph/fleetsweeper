// Package seal provides HMAC-SHA256 sealing for scan reports. The intent
// is auditor-grade tamper detection on saved or exported reports: an
// operator configures a secret with --seal-key, the same secret is used to
// produce a "seal" alongside the bundle, and "fleetsweeper verify" checks
// that the bundle's report bytes match the seal. The signature format and
// header conventions mirror the inbound webhook signature scheme so a
// single secret style is reusable across the tool.
package seal

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// Prefix is the algorithm tag emitted on every signature. The canonical
// header form is "sha256=<lowercase hex>", chosen for consistency with the
// inbound webhook signature header.
const Prefix = "sha256="

// FileName is the conventional filename used inside an export bundle to
// carry the signature of report.json. Kept as a constant so the export and
// verify code paths cannot drift apart.
const FileName = "report.sig"

// SourceFile is the bundle entry that the signature in FileName covers.
// Verification always re-signs SourceFile and compares against FileName.
const SourceFile = "report.json"

// ErrMissingKey is returned when sealing or verifying without a secret.
var ErrMissingKey = errors.New("seal: secret key is required")

// ErrMalformed is returned when a signature header is missing the
// expected "sha256=" prefix or is not valid hex.
var ErrMalformed = errors.New("seal: signature is malformed")

// ErrMismatch is returned when a signature does not match the data. This
// is the value to look for when reporting tamper detection.
var ErrMismatch = errors.New("seal: signature mismatch")

// Sign returns the canonical "sha256=<hex>" signature for data using key.
// Returns ErrMissingKey when key is empty so callers cannot accidentally
// produce a constant-zero seal.
func Sign(data []byte, key string) (string, error) {
	if key == "" {
		return "", ErrMissingKey
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(data)
	return Prefix + hex.EncodeToString(mac.Sum(nil)), nil
}

// SignReader streams from r and returns the canonical signature. Useful
// when sealing large reports without holding the full byte slice in memory.
func SignReader(r io.Reader, key string) (string, error) {
	if key == "" {
		return "", ErrMissingKey
	}
	mac := hmac.New(sha256.New, []byte(key))
	if _, err := io.Copy(mac, r); err != nil {
		return "", fmt.Errorf("seal: copy: %w", err)
	}
	return Prefix + hex.EncodeToString(mac.Sum(nil)), nil
}

// Verify recomputes the signature for data with key and constant-time
// compares it against signature. Returns ErrMalformed, ErrMissingKey, or
// ErrMismatch on failure so callers can distinguish operator error
// (missing key, wrong header format) from tamper detection.
func Verify(data []byte, signature, key string) error {
	if key == "" {
		return ErrMissingKey
	}
	provided, err := decodeSignature(signature)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, []byte(key))
	mac.Write(data)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, provided) {
		return ErrMismatch
	}
	return nil
}

// VerifyReader is the streaming variant of Verify. It exists so the
// verify command can validate a multi-megabyte report.json without
// allocating the full body up front.
func VerifyReader(r io.Reader, signature, key string) error {
	if key == "" {
		return ErrMissingKey
	}
	provided, err := decodeSignature(signature)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, []byte(key))
	if _, err := io.Copy(mac, r); err != nil {
		return fmt.Errorf("seal: copy: %w", err)
	}
	if !hmac.Equal(mac.Sum(nil), provided) {
		return ErrMismatch
	}
	return nil
}

// decodeSignature strips the algorithm prefix and hex-decodes the
// remainder. Returns ErrMalformed on any parse failure.
func decodeSignature(signature string) ([]byte, error) {
	signature = strings.TrimSpace(signature)
	if !strings.HasPrefix(signature, Prefix) {
		return nil, ErrMalformed
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(signature, Prefix))
	if err != nil {
		return nil, ErrMalformed
	}
	if len(raw) != sha256.Size {
		return nil, ErrMalformed
	}
	return raw, nil
}
