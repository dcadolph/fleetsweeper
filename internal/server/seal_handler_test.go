package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/seal"
	"github.com/dcadolph/fleetsweeper/internal/store"
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

// TestHandleGetScanSeal_ReturnsSignature verifies the endpoint signs the bundle MANIFEST, that
// two calls agree, and that the signature equals sealing the default bundle of the scan built
// at the scan's own time, which is what a default export writes.
func TestHandleGetScanSeal_ReturnsSignature(t *testing.T) {
	t.Parallel()
	srv, s := testServer(t)
	srv.sealKey = "topsecret"

	results := map[string]map[string]scanner.Result{
		"cluster-a": {"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}}},
	}
	at := time.Date(2026, 3, 1, 12, 30, 0, 0, time.UTC)
	scanID, err := s.SaveScanRecord(context.Background(),
		store.ScanRecord{Timestamp: at, Clusters: []string{"cluster-a"}}, results)
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}

	call := func() sealResponse {
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
		return resp
	}
	resp := call()
	if diff := cmp.Diff(resp, call()); diff != "" {
		t.Errorf("two calls differ (-first +second):\n%s", diff)
	}

	rpt := report.Build([]string{"cluster-a"}, results, report.BuildOptions{Timestamp: at})
	files, err := seal.BundleFiles(rpt, results, scanID, seal.BundleOptions{Sealed: true})
	if err != nil {
		t.Fatalf("bundle files: %v", err)
	}
	wantSig, err := seal.Bundle(files, "topsecret")
	if err != nil {
		t.Fatalf("seal bundle: %v", err)
	}
	want := sealResponse{
		ScanID:    scanID,
		Algorithm: "HMAC-SHA256",
		Source:    seal.ManifestFile,
		Signature: wantSig,
		Manifest:  string(files[seal.ManifestFile]),
	}
	if diff := cmp.Diff(want, resp); diff != "" {
		t.Errorf("response mismatch (-want +got):\n%s", diff)
	}
	for _, name := range []string{"report.json", "scan_results.json", "METADATA.txt"} {
		if !strings.Contains(resp.Manifest, "  "+name+"\n") {
			t.Errorf("manifest does not list %s:\n%s", name, resp.Manifest)
		}
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
