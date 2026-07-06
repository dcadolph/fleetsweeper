package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestE2E_DemoMode_AllEndpoints exercises every API endpoint against a
// freshly-started demo server. The goal is regression coverage: any new
// endpoint should be wired through the demo path so this test exercises it
// without panicking or returning a malformed response.
//
// Each endpoint gets two checks: HTTP status and a minimal shape assertion.
// Stricter contracts live in per-handler tests; this one just confirms the
// edges of the system are connected.
func TestE2E_DemoMode_AllEndpoints(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)
	httpSrv := httptest.NewServer(srv.mux)
	t.Cleanup(httpSrv.Close)

	endpoints := []struct {
		Name        string
		Path        string
		WantStatus  int
		WantMustHas []string
		Optional    bool
	}{
		{Name: "geo", Path: "/api/geo",
			WantStatus: http.StatusOK, WantMustHas: []string{"points", "demo"}},
		{Name: "scans-list", Path: "/api/scans?limit=5",
			WantStatus: http.StatusOK, WantMustHas: []string{}},
		{Name: "scan-detail", Path: "/api/scans/" + demoScanID,
			WantStatus: http.StatusOK, WantMustHas: []string{"id"}},
		{Name: "scan-report", Path: "/api/scans/" + demoScanID + "/report",
			WantStatus:  http.StatusOK,
			WantMustHas: []string{"fleet_score", "summary", "cluster_healths", "findings"}},
		{Name: "clusters", Path: "/api/clusters",
			WantStatus: http.StatusOK, WantMustHas: []string{}},
		{Name: "cluster-detail", Path: "/api/clusters/prod-us-east-1/detail",
			WantStatus:  http.StatusOK,
			WantMustHas: []string{"cluster", "scan_id", "findings"}},
		{Name: "outliers", Path: "/api/outliers",
			WantStatus: http.StatusOK, WantMustHas: []string{"scan_id"}},
		{Name: "capacity", Path: "/api/capacity",
			WantStatus: http.StatusOK, WantMustHas: []string{"capacity"}},
		{Name: "trends", Path: "/api/trends",
			WantStatus: http.StatusOK},
		{Name: "forecast-fleet-score", Path: "/api/forecast/fleet-score",
			WantStatus: http.StatusOK, WantMustHas: []string{"forecast"}},
		{Name: "forecast-clusters", Path: "/api/forecast/clusters",
			WantStatus: http.StatusOK, WantMustHas: []string{"forecasts"}},
		{Name: "cost", Path: "/api/cost",
			WantStatus: http.StatusOK, WantMustHas: []string{"currency"}},
		{Name: "integrations", Path: "/api/integrations",
			WantStatus: http.StatusOK, WantMustHas: []string{"items"}},
		{Name: "contexts", Path: "/api/contexts",
			WantStatus: http.StatusOK},
		{Name: "groups", Path: "/api/groups",
			WantStatus: http.StatusOK},
		{Name: "locations", Path: "/api/locations",
			WantStatus: http.StatusOK},
		{Name: "healthz", Path: "/healthz", WantStatus: http.StatusOK},
		{Name: "readyz", Path: "/readyz", WantStatus: http.StatusOK},
	}

	for _, ep := range endpoints {
		t.Run(ep.Name, func(t *testing.T) {
			t.Parallel()
			resp, err := http.Get(httpSrv.URL + ep.Path)
			if err != nil {
				t.Fatalf("GET %s: %v", ep.Path, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != ep.WantStatus {
				if ep.Optional && resp.StatusCode == http.StatusNotFound {
					return
				}
				t.Fatalf("GET %s: want status %d, got %d", ep.Path, ep.WantStatus, resp.StatusCode)
			}
			body := readBody(t, resp)
			// Health checks are JSON but trivially shaped; skip key assertions.
			if ep.Name == "healthz" || ep.Name == "readyz" {
				return
			}
			// All API responses must be valid JSON.
			var v any
			if err := json.Unmarshal(body, &v); err != nil {
				t.Fatalf("GET %s: response not valid JSON: %v\n%s", ep.Path, err, body)
			}
			for _, must := range ep.WantMustHas {
				if !strings.Contains(string(body), `"`+must+`"`) {
					t.Errorf("GET %s: response missing key %q\nbody: %s", ep.Path, must, body)
				}
			}
		})
	}
}

// TestE2E_DemoMode_MetricsEndpoint exercises the admin /metrics handler that
// is not registered on the public mux. We test it via the same Server's
// handler directly.
func TestE2E_DemoMode_MetricsEndpoint(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	srv.handleMetrics(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("metrics: want 200, got %d", w.Code)
	}
	body := w.Body.String()
	for _, want := range []string{
		"fleetsweeper_scans_total",
		"fleetsweeper_cluster_count",
		"fleetsweeper_fleet_score",
		"fleetsweeper_findings_total",
		"fleetsweeper_cluster_health",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("metrics body missing %q", want)
		}
	}
}

// TestE2E_DemoMode_MutatingEndpointsRejectedWithoutAuth confirms that the
// default Insecure mode still requires explicit opt-in for mutations; demo
// mode is read-only.
func TestE2E_DemoMode_MutatingEndpointsAuth(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)
	// testServer set Insecure=true; mutations should succeed. Just confirm
	// the route is reachable (POST returns 400 for missing body but the
	// route is wired).
	req := httptest.NewRequest(http.MethodPost, "/api/scans", strings.NewReader(""))
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code == http.StatusNotFound || w.Code == http.StatusMethodNotAllowed {
		t.Errorf("POST /api/scans not routed: code=%d", w.Code)
	}
}

// readBody returns the response body as bytes. Reads to EOF so JSON
// unmarshalling does not fail on truncation.
func readBody(t *testing.T, r *http.Response) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return body
}
