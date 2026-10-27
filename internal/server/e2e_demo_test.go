package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
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
			WantStatus: http.StatusOK, WantMustHas: []string{"points"}},
		{Name: "scans-list", Path: "/api/scans?limit=5",
			WantStatus: http.StatusOK, WantMustHas: []string{}},
		{Name: "scan-detail", Path: "/api/scans/" + demoScanIDAt(demoScans-1),
			WantStatus: http.StatusOK, WantMustHas: []string{"id"}},
		{Name: "scan-report", Path: "/api/scans/" + demoScanIDAt(demoScans-1) + "/report",
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

// newSealedDemoServer builds a demo server through New with --insecure off and a bootstrap
// token set, the way an operator would start one, so the demo's own auth resolution is what
// opens it and not a test override.
func newSealedDemoServer(t *testing.T) *Server {
	t.Helper()
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "demo.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	if err := SeedDemo(t.Context(), st, demoTestNow); err != nil {
		t.Fatalf("seed demo: %v", err)
	}
	srv := New(Config{
		Store:     st,
		Registry:  scanner.NewRegistry(),
		Log:       zap.NewNop(),
		Workers:   2,
		AuthToken: "ignored-in-demo",
		Demo:      true,
	})
	t.Cleanup(func() {
		srv.Close()
		st.Close()
	})
	return srv
}

// mutationCase is one write a demo visitor makes without a token.
type mutationCase struct {
	// Name labels the case in failures.
	Name string
	// Method is the HTTP method.
	Method string
	// Path is the request path under the server root.
	Path string
	// Body is the JSON request body.
	Body string
	// WantDemo is the status the demo returns with no token.
	WantDemo int
}

// demoMutations are the three writes every demo flow depends on: a triggered scan, an ack,
// and a tag write.
var demoMutations = []mutationCase{ //nolint:gochecknoglobals // Not modified, simplifies testing.
	{Name: "trigger", Method: http.MethodPost, Path: "/api/scans",
		Body: `{"all_contexts":true}`, WantDemo: http.StatusAccepted},
	{Name: "ack", Method: http.MethodPost, Path: "/api/findings/abc123/ack",
		Body: `{"cluster":"fleet","reason":"demo"}`, WantDemo: http.StatusCreated},
	{Name: "tag", Method: http.MethodPut, Path: "/api/clusters/prod-us-east-1/tags/cohort",
		Body: `{"value":"edge"}`, WantDemo: http.StatusOK},
}

// TestE2E_DemoMode_MutationsOpen asserts demo mode turns auth off: a trigger, an ack, and a
// tag write succeed with no token even though --insecure is off and a token is configured.
// It inverts the earlier assertion that demo mutations without a token are rejected.
func TestE2E_DemoMode_MutationsOpen(t *testing.T) {
	t.Parallel()
	srv := newSealedDemoServer(t)
	for _, tc := range demoMutations {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(tc.Method, tc.Path, strings.NewReader(tc.Body)))
		if w.Code != tc.WantDemo {
			t.Errorf("%s: want %d without a token in demo, got %d body=%s", tc.Name, tc.WantDemo, w.Code,
				w.Body.String())
		}
	}
	srv.bg.Wait()
}

// TestE2E_NonDemo_MutationsNeedToken asserts the same three writes still return 401 without
// a token outside demo mode, so opening the demo did not open the real server.
func TestE2E_NonDemo_MutationsNeedToken(t *testing.T) {
	t.Parallel()
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "real.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	srv := New(Config{
		Store:     st,
		Registry:  scanner.NewRegistry(),
		Log:       zap.NewNop(),
		Workers:   2,
		AuthToken: "real-token",
	})
	t.Cleanup(func() {
		srv.Close()
		st.Close()
	})
	for _, tc := range demoMutations {
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, httptest.NewRequest(tc.Method, tc.Path, strings.NewReader(tc.Body)))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s: want 401 without a token outside demo, got %d", tc.Name, w.Code)
		}
	}
}

// TestE2E_DemoMode_AuthLabels asserts the system status and the integrations list name demo
// mode instead of labeling the demo insecure.
func TestE2E_DemoMode_AuthLabels(t *testing.T) {
	t.Parallel()
	srv := newSealedDemoServer(t)

	w := httptest.NewRecorder()
	srv.handleAdminSystem(w, httptest.NewRequest(http.MethodGet, "/admin/system", nil))
	var sys systemResponse
	if err := json.Unmarshal(w.Body.Bytes(), &sys); err != nil {
		t.Fatalf("decode system: %v", err)
	}
	if diff := cmp.Diff(systemFeatures{Demo: true}, sys.Features); diff != "" {
		t.Errorf("system features mismatch (-want +got):\n%s", diff)
	}

	w = httptest.NewRecorder()
	srv.handleGetIntegrations(w, httptest.NewRequest(http.MethodGet, "/api/integrations", nil))
	var integ integrationsResponse
	if err := json.Unmarshal(w.Body.Bytes(), &integ); err != nil {
		t.Fatalf("decode integrations: %v", err)
	}
	i := slices.IndexFunc(integ.Items, func(it integrationStatus) bool { return it.Name == "Bearer auth" })
	if i < 0 {
		t.Fatal("no Bearer auth row")
	}
	if diff := cmp.Diff("off (demo)", integ.Items[i].Status); diff != "" {
		t.Errorf("bearer status mismatch (-want +got):\n%s", diff)
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
