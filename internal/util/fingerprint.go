// Package util holds small helpers shared across packages so a single
// implementation is imported everywhere rather than duplicated.
package util

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint returns a stable hex identifier for a finding, derived from the
// cluster, scanner, and title separated by null bytes. Acknowledgements key on
// the same value, so a finding can be matched to its ack and tracked across
// scans by fingerprint.
func Fingerprint(cluster, scanner, title string) string {
	h := sha256.New()
	h.Write([]byte(cluster))
	h.Write([]byte{0})
	h.Write([]byte(scanner))
	h.Write([]byte{0})
	h.Write([]byte(title))
	return hex.EncodeToString(h.Sum(nil))
}
