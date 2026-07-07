package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleWebhookScanTrigger_EmptyBody verifies that a validly-signed empty
// body progresses past the signature gate and into context resolution. The
// exact status depends on the test environment's kubeconfig, so the assertion
// only confirms the request cleared authentication.
func TestHandleWebhookScanTrigger_EmptyBody(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.webhookSecret = "topsecret"
	srv.kubeconfigPath = "/nonexistent/kubeconfig-for-test"

	body := []byte{}
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/scan-trigger",
		bytes.NewReader(body))
	req.Header.Set(webhookSignatureHeader, signWebhookBody("topsecret", body))
	w := httptest.NewRecorder()
	srv.handleWebhookScanTrigger(w, req)

	if w.Code == http.StatusUnauthorized || w.Code == http.StatusNotFound {
		t.Errorf("expected handler to clear the signature gate; got %d", w.Code)
	}
}
