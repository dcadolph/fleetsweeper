// Package util holds small helpers shared across packages so a single
// implementation is imported everywhere rather than duplicated.
package util

import (
	"crypto/sha256"
	"encoding/hex"
)

// Fingerprint returns a stable hex identifier for a finding, derived from the
// cluster, scanner, and rule separated by null bytes. The rule names the check
// rather than its wording, so a finding keeps its fingerprint when a count in
// its title changes. Acknowledgements key on the same value, so a finding can
// be matched to its ack and tracked across scans by fingerprint.
func Fingerprint(cluster, scanner, rule string) string {
	h := sha256.New()
	h.Write([]byte(cluster))
	h.Write([]byte{0})
	h.Write([]byte(scanner))
	h.Write([]byte{0})
	h.Write([]byte(rule))
	return hex.EncodeToString(h.Sum(nil))
}
