package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHandleGetFleetScoreForecast_Seeded exercises the non-demo history
// walk by seeding several scans and asserting the handler returns a history
// series and a forecast.
func TestHandleGetFleetScoreForecast_Seeded(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	for range 3 {
		seedScan(t, ss, "east", "west")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/forecast/fleet-score?scans=5", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		History  []map[string]any `json:"history"`
		Forecast map[string]any   `json:"forecast"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.History) != 3 {
		t.Errorf("expected 3 history points, got %d", len(resp.History))
	}
	if resp.Forecast == nil {
		t.Error("missing forecast object")
	}
}

// TestHandleGetClusterForecasts_Seeded exercises the per-cluster history
// aggregation over multiple stored scans.
func TestHandleGetClusterForecasts_Seeded(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	for range 3 {
		seedScan(t, ss, "east", "west")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/forecast/clusters", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Forecasts []clusterForecast `json:"forecasts"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Forecasts) != 2 {
		t.Errorf("expected 2 cluster forecasts, got %d", len(resp.Forecasts))
	}
}
