package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/report"
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

	contexts, err := s.resolveContexts(r.Context(), req)
	if err != nil {
		writeError(w, http.StatusBadRequest, safeMessage(err, "invalid contexts"))
		return
	}
	if len(contexts) == 0 {
		// Default behavior for an empty body: scan every available context.
		contexts, err = kube.AvailableContexts(s.kubeconfigPath)
		if err != nil {
			writeError(w, http.StatusBadRequest, safeMessage(err, "no contexts available"))
			return
		}
	}

	if !s.scanBusy.CompareAndSwap(false, true) {
		writeError(w, http.StatusTooManyRequests, "scan in progress; retry later")
		return
	}

	go s.runInboundScan(contexts)
	writeJSON(w, http.StatusAccepted, triggerScanResponse{Status: "running"})
}

// runInboundScan mirrors the goroutine path in handleTriggerScan. Lives
// here so the inbound webhook flow does not have to duplicate scan
// completion plumbing (acks, slack, fleetdrift, policyreport, webhooks).
func (s *Server) runInboundScan(contexts []string) {
	defer s.scanBusy.Store(false)
	s.scanMu.Lock()
	defer s.scanMu.Unlock()

	ctx := s.ctx
	started := time.Now()
	s.log.Info("inbound webhook scan starting", zap.Int("contexts", len(contexts)))

	clients := kube.ConnectAll(ctx, s.kubeconfigPath, contexts, s.workers)
	if len(clients) == 0 {
		s.scansErr.Add(1)
		s.recordScanCompletion(false)
		s.log.Warn("inbound webhook scan: no clusters reachable")
		return
	}

	results := runScanners(ctx, clients, s.registry.All(), s.workers, s.log)
	clusterNames := make([]string, len(clients))
	for i, c := range clients {
		clusterNames[i] = c.Context
	}

	scanID, err := s.store.SaveScan(ctx, clusterNames, results)
	if err != nil {
		s.scansErr.Add(1)
		s.recordScanCompletion(false)
		s.log.Error("inbound webhook scan: save failed", zap.Error(err))
		return
	}
	s.scansOK.Add(1)
	s.recordScanDuration(time.Since(started))
	s.recordScanCompletion(true)
	s.log.Info("inbound webhook scan complete", zap.String("scan_id", scanID))
	rpt := report.Build(clusterNames, results)
	s.notifySlackForReport(ctx, rpt)
	s.writeFleetDriftIfConfigured(rpt, scanID)
	s.writePolicyReportIfConfigured(rpt, scanID)
	s.dispatchWebhooksIfConfigured(ctx, rpt)
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

// signedBytes returns the raw signature bytes for a body. Useful when tests
// want to inspect signature length or assemble a custom header.
func signedBytes(secret string, body []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return mac.Sum(nil)
}

// _ silences the unused-helper lint for signedBytes; the helper exists for
// future test wiring and is intentionally exported within the package.
var _ = bytes.Equal
var _ = signedBytes
