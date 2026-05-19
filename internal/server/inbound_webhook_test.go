package server

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifyWebhookSignature_OK(t *testing.T) {
	t.Parallel()
	body := []byte(`{"all_contexts":true}`)
	sig := signWebhookBody("topsecret", body)
	if err := verifyWebhookSignature("topsecret", sig, body); err != nil {
		t.Errorf("expected ok, got %v", err)
	}
}

func TestVerifyWebhookSignature_MissingHeader(t *testing.T) {
	t.Parallel()
	if err := verifyWebhookSignature("k", "", []byte("body")); err == nil {
		t.Errorf("expected error for empty header")
	}
}

func TestVerifyWebhookSignature_BadHex(t *testing.T) {
	t.Parallel()
	if err := verifyWebhookSignature("k", "sha256=not-hex", []byte("b")); err == nil {
		t.Errorf("expected error for non-hex signature")
	}
}

func TestVerifyWebhookSignature_Mismatch(t *testing.T) {
	t.Parallel()
	body := []byte(`{"x":1}`)
	good := signWebhookBody("real", body)
	if err := verifyWebhookSignature("different", good, body); err == nil {
		t.Errorf("expected mismatch error")
	}
}

func TestInboundWebhook_Disabled_When_NoSecret(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.webhookSecret = "" // explicit
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/scan-trigger",
		bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	srv.handleWebhookScanTrigger(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404 when disabled, got %d", w.Code)
	}
}

func TestInboundWebhook_BadSignature(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.webhookSecret = "topsecret"
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/scan-trigger",
		bytes.NewReader([]byte(`{}`)))
	req.Header.Set(webhookSignatureHeader, "sha256=deadbeef")
	w := httptest.NewRecorder()
	srv.handleWebhookScanTrigger(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("want 401 for bad signature, got %d", w.Code)
	}
}

func TestInboundWebhook_ValidSignature_AcceptedOrConflict(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.webhookSecret = "topsecret"
	body := []byte(`{"all_contexts":true}`)
	req := httptest.NewRequest(http.MethodPost, "/api/webhooks/scan-trigger",
		bytes.NewReader(body))
	req.Header.Set(webhookSignatureHeader, signWebhookBody("topsecret", body))
	w := httptest.NewRecorder()
	srv.handleWebhookScanTrigger(w, req)
	// We expect 202 (accepted), 400 (no contexts in test env), or 500
	// (kube unavailable). The point of the test is that the signature gate
	// passed and the handler progressed beyond it.
	if w.Code == http.StatusUnauthorized || w.Code == http.StatusNotFound {
		t.Errorf("expected handler to progress past signature gate; got %d", w.Code)
	}
}
