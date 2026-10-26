// Package seal provides HMAC-SHA256 sealing for export bundles. The intent is auditor-grade
// tamper detection: an operator configures a secret with --seal-key, the bundle carries a
// MANIFEST that lists every file with its SHA-256, the secret signs the MANIFEST, and
// "fleetsweeper verify" checks the signature and then every file against the MANIFEST. The
// signature format and header conventions mirror the inbound webhook signature scheme so a
// single secret style is reusable across the tool.
package seal

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

// Prefix is the algorithm tag emitted on every signature. The canonical
// header form is "sha256=<lowercase hex>", chosen for consistency with the
// inbound webhook signature header.
const Prefix = "sha256="

// ManifestFile is the bundle entry listing every other file with its SHA-256. The signature
// covers it, so it vouches for every file it lists.
const ManifestFile = "MANIFEST"

// FileName is the bundle entry carrying the signature of ManifestFile.
const FileName = "MANIFEST.sig"

// ErrMissingKey is returned when sealing or verifying without a secret.
var ErrMissingKey = errors.New("seal: secret key is required")

// ErrMalformed is returned when a signature header is missing the
// expected "sha256=" prefix or is not valid hex.
var ErrMalformed = errors.New("seal: signature is malformed")

// ErrMismatch is returned when a signature does not match the data. This
// is the value to look for when reporting tamper detection.
var ErrMismatch = errors.New("seal: signature mismatch")

// ErrManifest is returned when a MANIFEST cannot be parsed.
var ErrManifest = errors.New("seal: manifest is malformed")

// ErrContents is returned when a bundle's files do not match its MANIFEST: a listed file is
// missing or altered, or a file is not listed.
var ErrContents = errors.New("seal: bundle contents do not match the manifest")

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

// Manifest returns the MANIFEST for files, keyed by path relative to the bundle root: one
// "<sha256 hex>  <path>" line per file, sorted by path, the layout sha256sum writes. Entries
// named ManifestFile or FileName are left out.
func Manifest(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for name := range files {
		if name == ManifestFile || name == FileName {
			continue
		}
		names = append(names, name)
	}
	slices.Sort(names)
	var b bytes.Buffer
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	return b.Bytes()
}

// CheckManifest verifies that files match manifest exactly: every listed file is present with
// the listed digest, and every file other than ManifestFile and FileName is listed. It does not
// check the signature; callers verify the manifest's signature first. The error wraps
// ErrContents and names each missing, altered, and unlisted file.
func CheckManifest(manifest []byte, files map[string][]byte) error {
	listed := make(map[string]string)
	sc := bufio.NewScanner(bytes.NewReader(manifest))
	for sc.Scan() {
		sum, name, ok := strings.Cut(sc.Text(), "  ")
		if !ok || name == "" || len(sum) != 2*sha256.Size {
			return fmt.Errorf("%w: line %q", ErrManifest, sc.Text())
		}
		if _, dup := listed[name]; dup {
			return fmt.Errorf("%w: %s listed twice", ErrManifest, name)
		}
		listed[name] = sum
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("%w: %w", ErrManifest, err)
	}

	var problems []string
	for name, want := range listed {
		data, ok := files[name]
		if !ok {
			problems = append(problems, "missing "+name)
			continue
		}
		got := sha256.Sum256(data)
		if hex.EncodeToString(got[:]) != want {
			problems = append(problems, "altered "+name)
		}
	}
	for name := range files {
		if _, ok := listed[name]; !ok && name != ManifestFile && name != FileName {
			problems = append(problems, "unlisted "+name)
		}
	}
	if len(problems) > 0 {
		slices.Sort(problems)
		return fmt.Errorf("%w: %s", ErrContents, strings.Join(problems, ", "))
	}
	return nil
}
