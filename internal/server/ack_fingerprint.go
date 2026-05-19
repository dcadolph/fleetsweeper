package server

import "github.com/dcadolph/fleetsweeper/internal/store"

// storeAckFingerprint is a tiny re-export of store.AckFingerprint so the
// server package can compute fingerprints without dragging the store import
// into every file that filters findings.
func storeAckFingerprint(cluster, scanner, title string) string {
	return store.AckFingerprint(cluster, scanner, title)
}
