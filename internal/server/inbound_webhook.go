package server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// webhookSignatureHeader is the HTTP header inbound callers must use to
// carry the HMAC-SHA256 signature of the request body. Format follows the
// well-known GitHub/Stripe convention: "sha256=<hex digest>".
const webhookSignatureHeader = "X-Fleetsweeper-Signature"

// webhookSignaturePrefix is the algorithm tag we accept on signature headers.
const webhookSignaturePrefix = "sha256="

// handleWebhookScanTrigger validates an HMAC-signed POST and, when valid,
// kicks off a scan asynchronously. Intended for GitHub/GitLab/Argo CD
// merge-event hooks: "the canonical Helm chart landed; rescan the fleet".
//
// Disabled (404) when --webhook-secret is not configured so an unsigned
// endpoint cannot be left exposed by mistake.
func (s *Server) handleWebhookScanTrigger(w http.ResponseWriter, r *http.Request) {
	if s.webhookSecret == "" {
		writeError(w, http.StatusNotFound, "inbound webhook disabled")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 64*1024))
	if err != nil {
		writeError(w, http.StatusBadRequest, "body too large or unreadable")
		return
	}
	if err := verifyWebhookSignature(s.webhookSecret,
		r.Header.Get(webhookSignatureHeader), body); err != nil {
		s.log.Warn("inbound webhook: signature rejected", zap.Error(err))
		writeError(w, http.StatusUnauthorized, "invalid signature")
		return
	}

	var req triggerScanRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid JSON body")
			return
		}
	}

	// An empty request scans every available context.
	if len(req.Contexts) == 0 && req.Group == "" {
		req.AllContexts = true
	}
	contexts, err := s.resolveContexts(r.Context(), req)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusBadRequest, safeMessage(err, "group not found"))
			return
		}
		s.log.Error("inbound webhook: resolve contexts", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "resolve contexts failed")
		return
	}
	if len(contexts) == 0 {
		writeError(w, http.StatusBadRequest, "no contexts available")
		return
	}

	scanID, ok := s.startBackgroundScan(scanSourceInbound, contexts)
	if !ok {
		writeError(w, http.StatusTooManyRequests, "scan in progress; retry later")
		return
	}
	writeJSON(w, http.StatusAccepted, triggerScanResponse{ScanID: scanID, Status: "running"})
}

// verifyWebhookSignature constant-time-compares the HMAC-SHA256 of body
// (using secret) against the provided header value. Header format:
// "sha256=<lowercase hex>".
func verifyWebhookSignature(secret, header string, body []byte) error {
	if !strings.HasPrefix(header, webhookSignaturePrefix) {
		return errors.New("missing or malformed signature header")
	}
	provided, err := hex.DecodeString(strings.TrimPrefix(header, webhookSignaturePrefix))
	if err != nil {
		return errors.New("signature is not valid hex")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := mac.Sum(nil)
	if !hmac.Equal(expected, provided) {
		return errors.New("signature mismatch")
	}
	return nil
}

// signWebhookBody is a helper exposed for tests and tooling that need to
// produce a valid signature. Returns the value to use as the
// X-Fleetsweeper-Signature header.
func signWebhookBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return webhookSignaturePrefix + hex.EncodeToString(mac.Sum(nil))
}
