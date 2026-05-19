package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/seal"
)

func TestHandleGetScanSeal_DisabledWhenNoKey(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.sealKey = ""
	req := httptest.NewRequest(http.MethodGet, "/api/scans/whatever/seal", nil)
	req.SetPathValue("id", "whatever")
	w := httptest.NewRecorder()
	srv.handleGetScanSeal(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404 when disabled, got %d", w.Code)
	}
}

func TestHandleGetScanSeal_ReturnsSignature(t *testing.T) {
	t.Parallel()
	srv, s := testServer(t)
	srv.sealKey = "topsecret"

	results := map[string]map[string]scanner.Result{
		"cluster-a": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}}},
	}
	scanID, err := s.SaveScan(context.Background(), []string{"cluster-a"}, results)
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/scans/"+scanID+"/seal", nil)
	req.SetPathValue("id", scanID)
	w := httptest.NewRecorder()
	srv.handleGetScanSeal(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d (body: %s)", w.Code, w.Body.String())
	}
	var resp sealResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.ScanID != scanID {
		t.Errorf("scan id: got %q want %q", resp.ScanID, scanID)
	}
	if !strings.HasPrefix(resp.Signature, seal.Prefix) {
		t.Errorf("expected signature with %q prefix, got %q", seal.Prefix, resp.Signature)
	}
	if resp.Algorithm != "HMAC-SHA256" {
		t.Errorf("algorithm: got %q want HMAC-SHA256", resp.Algorithm)
	}
}

func TestHandleGetScanSeal_UnknownScan(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.sealKey = "topsecret"
	req := httptest.NewRequest(http.MethodGet, "/api/scans/missing/seal", nil)
	req.SetPathValue("id", "missing")
	w := httptest.NewRecorder()
	srv.handleGetScanSeal(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404 for unknown scan, got %d", w.Code)
	}
}
