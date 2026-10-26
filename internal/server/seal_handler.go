package server

import (
	"net/http"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/seal"
)

// sealResponse is the JSON body returned by /api/scans/{id}/seal. The signature covers the
// MANIFEST of the export bundle "fleetsweeper export --seal-key" writes for the same scan with
// default options, so the two always agree.
type sealResponse struct {
	// ScanID is the scan whose bundle was sealed.
	ScanID string `json:"scan_id"`
	// Algorithm names the digest used. Always "HMAC-SHA256".
	Algorithm string `json:"algorithm"`
	// Source identifies the bytes that the signature covers.
	Source string `json:"source"`
	// Signature is the sealed value in "sha256=<hex>" form.
	Signature string `json:"signature"`
	// Manifest is the signed MANIFEST: one "<sha256>  <path>" line per bundle file.
	Manifest string `json:"manifest"`
}

// handleGetScanSeal rebuilds the export bundle of a stored scan and returns the HMAC-SHA256
// signature of its MANIFEST. The bundle is deterministic, so the same scan returns the same
// signature on every call and matches an export made with default options. Disabled (404) when
// the server was started without --seal-key so an operator cannot accidentally emit unsealed
// responses that downstream consumers treat as trusted.
//
// Useful for audit pipelines that need a tamper-evident handle on a scan without downloading
// the full export bundle: scrape /seal periodically and store the value in a write-only log.
func (s *Server) handleGetScanSeal(w http.ResponseWriter, r *http.Request) {
	if s.sealKey == "" {
		writeError(w, http.StatusNotFound, "sealing disabled")
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()

	scan, err := s.store.GetScan(ctx, id)
	if err != nil {
		s.writeStoreError(w, err, "get scan", "scan not found")
		return
	}
	results, err := s.store.GetScanResults(ctx, id)
	if err != nil {
		s.log.Error("get scan results", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "get scan results failed")
		return
	}
	rpt := report.Build(scan.Clusters, results, report.BuildOptions{Timestamp: scan.Timestamp})
	files, err := seal.BundleFiles(rpt, results, scan.ID, seal.BundleOptions{Sealed: true})
	if err != nil {
		s.log.Error("build bundle", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "build bundle failed")
		return
	}
	sig, err := seal.SealBundle(files, s.sealKey)
	if err != nil {
		s.log.Error("seal bundle", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "seal failed")
		return
	}
	writeJSON(w, http.StatusOK, sealResponse{
		ScanID:    id,
		Algorithm: "HMAC-SHA256",
		Source:    seal.ManifestFile,
		Signature: sig,
		Manifest:  string(files[seal.ManifestFile]),
	})
}
