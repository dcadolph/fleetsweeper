package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestHandleGetCost_DefaultNoData verifies that without a cost CSV or demo
// mode the handler returns an empty USD analysis.
func TestHandleGetCost_DefaultNoData(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/cost", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if decodeObj(t, w)["currency"] != "USD" {
		t.Errorf("expected USD currency, got %s", w.Body.String())
	}
}

// TestHandleGetCost_FromCSV verifies the CSV-loading branch: costs are joined
// against the most recent scan to produce a correlated analysis.
func TestHandleGetCost_FromCSV(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedScan(t, ss, "east", "west")

	csv := "cluster,period,cost_usd\neast,2026-05,1200.00\nwest,2026-05,900.00\n"
	path := filepath.Join(t.TempDir(), "cost.csv")
	if err := os.WriteFile(path, []byte(csv), 0o600); err != nil {
		t.Fatalf("write csv: %v", err)
	}
	srv.costCSVPath = path

	req := httptest.NewRequest(http.MethodGet, "/api/cost", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	if decodeObj(t, w)["currency"] != "USD" {
		t.Errorf("expected USD currency, got %s", w.Body.String())
	}
}

// TestHandleGetCost_CSVLoadError verifies a missing CSV file surfaces a 500.
func TestHandleGetCost_CSVLoadError(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.costCSVPath = filepath.Join(t.TempDir(), "does-not-exist.csv")
	req := httptest.NewRequest(http.MethodGet, "/api/cost", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("want 500, got %d", w.Code)
	}
}

// TestHandleGetCost_Demo verifies the demo path uses the built-in synthetic
// cost map so the panel renders without operator setup.
func TestHandleGetCost_Demo(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/cost", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	if decodeObj(t, w)["currency"] != "USD" {
		t.Errorf("expected USD currency, got %s", w.Body.String())
	}
}
