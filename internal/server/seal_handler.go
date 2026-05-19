package server

import (
	"encoding/json"
	"net/http"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/seal"
)

// sealResponse is the JSON body returned by /api/scans/{id}/seal. The
// Algorithm field documents the digest used so verifiers do not have to
// guess; the Source field names the bytes that the signature covers (the
// canonical report.json that "fleetsweeper export" would write).
type sealResponse struct {
	// ScanID is the scan whose report was sealed.
	ScanID string `json:"scan_id"`
	// Algorithm names the digest used. Always "HMAC-SHA256".
	Algorithm string `json:"algorithm"`
	// Source identifies the bytes that the signature covers.
	Source string `json:"source"`
	// Signature is the sealed value in "sha256=<hex>" form.
	Signature string `json:"signature"`
	// IssuedAt is the timestamp the server computed the seal.
	IssuedAt time.Time `json:"issued_at"`
}

// handleGetScanSeal computes and returns the HMAC-SHA256 signature of the
// canonical report bytes for a stored scan. Disabled (404) when the
// server was started without --seal-key so an operator cannot accidentally
// emit unsealed responses that downstream consumers treat as trusted.
//
// Useful for audit pipelines that need a tamper-evident handle on a scan
// without downloading the full export bundle: scrape /seal periodically
// and store the value in a write-only log.
func (s *Server) handleGetScanSeal(w http.ResponseWriter, r *http.Request) {
	if s.sealKey == "" {
		writeError(w, http.StatusNotFound, "sealing disabled")
		return
	}
	id := r.PathValue("id")
	ctx := r.Context()

	scan, err := s.store.GetScan(ctx, id)
	if err != nil {
		writeError(w, http.StatusNotFound, "scan not found")
		return
	}
	results, err := s.store.GetScanResults(ctx, id)
	if err != nil {
		s.log.Error("get scan results", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "get scan results failed")
		return
	}
	rpt := report.Build(scan.Clusters, results)
	body, err := json.Marshal(rpt)
	if err != nil {
		s.log.Error("marshal report", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "marshal report failed")
		return
	}
	sig, err := seal.Sign(body, s.sealKey)
	if err != nil {
		s.log.Error("sign report", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "sign failed")
		return
	}
	writeJSON(w, http.StatusOK, sealResponse{
		ScanID:    id,
		Algorithm: "HMAC-SHA256",
		Source:    seal.SourceFile,
		Signature: sig,
		IssuedAt:  time.Now().UTC(),
	})
}
