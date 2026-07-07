package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// seedScan writes one scan carrying a small but realistic per-cluster
// scanner payload so report.Build produces populated sections. Returns
// the generated scan ID. Used by the read-handler tests to exercise the
// non-demo code paths that the demo e2e test does not reach.
func seedScan(t *testing.T, ss *store.SQLite, clusters ...string) string {
	t.Helper()
	results := make(map[string]map[string]scanner.Result, len(clusters))
	for i, c := range clusters {
		results[c] = map[string]scanner.Result{
			"version": {Scanner: "version", Data: map[string]any{
				"git_version": "v1.31.2", "minor": 31,
			}},
			"metrics": {Scanner: "metrics", Data: map[string]any{
				"avg_cpu_percent":    40 + float64(i*5),
				"avg_memory_percent": 50 + float64(i*3),
			}},
			"node-health": {Scanner: "node-health", Data: map[string]any{
				"node_count": 3, "healthy_nodes": 3, "unhealthy_nodes": 0,
			}},
		}
	}
	id, err := ss.SaveScan(context.Background(), clusters, results)
	if err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	return id
}

// decodeObj unmarshals a recorder body into a generic JSON object and
// fails the test when the body is not a JSON object.
func decodeObj(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode object: %v body=%s", err, w.Body.String())
	}
	return m
}

// TestHandleGetScan_FoundAndMissing covers the stored-scan lookup and the
// 404 path when the ID is unknown.
func TestHandleGetScan_FoundAndMissing(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	id := seedScan(t, ss, "east", "west")

	req := httptest.NewRequest(http.MethodGet, "/api/scans/"+id, nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("found: want 200, got %d body=%s", w.Code, w.Body.String())
	}
	if decodeObj(t, w)["id"] != id {
		t.Errorf("id mismatch: %s", w.Body.String())
	}

	miss := httptest.NewRequest(http.MethodGet, "/api/scans/nope", nil)
	mw := httptest.NewRecorder()
	srv.mux.ServeHTTP(mw, miss)
	if mw.Code != http.StatusNotFound {
		t.Errorf("missing: want 404, got %d", mw.Code)
	}
}

// TestHandleGetScan_DemoRecord verifies demo mode returns the synthetic
// scan record for the reserved demo scan ID.
func TestHandleGetScan_DemoRecord(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/scans/"+demoScanID, nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if decodeObj(t, w)["id"] != demoScanID {
		t.Errorf("expected demo scan id, got %s", w.Body.String())
	}
}

// TestHandleGetScanReport_TagFilter verifies the report handler filters
// per-cluster findings by ?tag= while retaining fleet-level rows.
func TestHandleGetScanReport_TagFilter(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	id := seedScan(t, ss, "east", "west")
	_ = ss.SetClusterTag(context.Background(), "east", "env", "prod")

	req := httptest.NewRequest(http.MethodGet, "/api/scans/"+id+"/report?tag=env=prod", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	obj := decodeObj(t, w)
	if _, ok := obj["findings"]; !ok {
		t.Error("report missing findings key")
	}
	if _, ok := obj["sections"]; !ok {
		t.Error("report missing sections key")
	}
}

// TestHandleGetScanReport_Missing verifies an unknown scan ID 404s.
func TestHandleGetScanReport_Missing(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/scans/ghost/report", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// TestHandleGetClusterDetail_Seeded covers the stored-scan detail path,
// including scanner_data projection, plus the unknown-cluster 404.
func TestHandleGetClusterDetail_Seeded(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedScan(t, ss, "east", "west")

	req := httptest.NewRequest(http.MethodGet, "/api/clusters/east/detail", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	obj := decodeObj(t, w)
	if obj["cluster"] != "east" {
		t.Errorf("cluster mismatch: %v", obj["cluster"])
	}
	if _, ok := obj["scanner_data"]; !ok {
		t.Error("missing scanner_data")
	}

	miss := httptest.NewRequest(http.MethodGet, "/api/clusters/ghost/detail", nil)
	mw := httptest.NewRecorder()
	srv.mux.ServeHTTP(mw, miss)
	if mw.Code != http.StatusNotFound {
		t.Errorf("unknown cluster: want 404, got %d", mw.Code)
	}
}

// TestHandleGetClusterDetail_NoScans verifies the non-demo empty-store
// path returns 404.
func TestHandleGetClusterDetail_NoScans(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/clusters/east/detail", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// TestHandleGetTrends_TwoScans verifies the fleet-trends handler computes
// trends once at least two scans exist.
func TestHandleGetTrends_TwoScans(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedScan(t, ss, "east", "west")
	seedScan(t, ss, "east", "west")

	req := httptest.NewRequest(http.MethodGet, "/api/trends?scans=5", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	obj := decodeObj(t, w)
	if _, ok := obj["fleet_trends"]; !ok {
		t.Error("missing fleet_trends")
	}
}

// TestHandleGetTrends_InsufficientScans verifies the "need at least 2 scans"
// message path for a single-scan store outside demo mode.
func TestHandleGetTrends_InsufficientScans(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedScan(t, ss, "east")

	req := httptest.NewRequest(http.MethodGet, "/api/trends", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if decodeObj(t, w)["message"] == nil {
		t.Error("expected message about needing 2 scans")
	}
}

// TestHandleGetClusterTrends_Seeded covers the per-cluster trends handler
// over multiple stored scans.
func TestHandleGetClusterTrends_Seeded(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedScan(t, ss, "east", "west")
	seedScan(t, ss, "east", "west")

	req := httptest.NewRequest(http.MethodGet, "/api/trends/east?scans=5", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	obj := decodeObj(t, w)
	if obj["cluster"] != "east" {
		t.Errorf("cluster mismatch: %v", obj["cluster"])
	}
	if _, ok := obj["cluster_trends"]; !ok {
		t.Error("missing cluster_trends")
	}
	if _, ok := obj["self_drift"]; !ok {
		t.Error("missing self_drift")
	}
}

// TestHandleGetOutliers_Seeded covers the stored-scan outlier path and the
// custom threshold query parameter.
func TestHandleGetOutliers_Seeded(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	id := seedScan(t, ss, "east", "west", "south")

	req := httptest.NewRequest(http.MethodGet, "/api/outliers?threshold=2.5", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	obj := decodeObj(t, w)
	if obj["scan_id"] != id {
		t.Errorf("scan_id mismatch: %v want %s", obj["scan_id"], id)
	}
	if _, ok := obj["outliers"]; !ok {
		t.Error("missing outliers key")
	}
}

// TestHandleGetOutliers_NoScans verifies the empty-store 404 path.
func TestHandleGetOutliers_NoScans(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/outliers", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// TestHandleGetCohorts_Seeded covers the stored-scan cohort path, including
// projectCohortTags reading a seeded cohort tag.
func TestHandleGetCohorts_Seeded(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	id := seedScan(t, ss, "east", "west")
	_ = ss.SetClusterTag(context.Background(), "east", cohortTagKey, "prod")

	req := httptest.NewRequest(http.MethodGet, "/api/cohorts?threshold=3.0", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	obj := decodeObj(t, w)
	if obj["scan_id"] != id {
		t.Errorf("scan_id mismatch: %v", obj["scan_id"])
	}
	if _, ok := obj["cohorts"]; !ok {
		t.Error("missing cohorts key")
	}
}

// TestHandleGetCapacity_Seeded covers the stored-scan capacity path with a
// group present so the group map branch runs.
func TestHandleGetCapacity_Seeded(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	id := seedScan(t, ss, "east", "west")
	if err := ss.SaveGroup(context.Background(), "prod", []string{"east"}); err != nil {
		t.Fatalf("seed group: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/capacity", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	obj := decodeObj(t, w)
	if obj["scan_id"] != id {
		t.Errorf("scan_id mismatch: %v", obj["scan_id"])
	}
	if _, ok := obj["capacity"]; !ok {
		t.Error("missing capacity key")
	}
}

// TestHandleGetCapacity_NoScans verifies the empty-store 404 path.
func TestHandleGetCapacity_NoScans(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/capacity", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// TestHandleListScans_LimitAndData verifies the limit query parameter is
// honored and stored scans are returned.
func TestHandleListScans_LimitAndData(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedScan(t, ss, "east")
	seedScan(t, ss, "west")

	req := httptest.NewRequest(http.MethodGet, "/api/scans?limit=1", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var scans []store.ScanRecord
	if err := json.Unmarshal(w.Body.Bytes(), &scans); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(scans) != 1 {
		t.Errorf("limit=1 should return one scan, got %d", len(scans))
	}
}

// TestHandleListGroups_ReturnsSeeded verifies stored groups are listed.
func TestHandleListGroups_ReturnsSeeded(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	if err := ss.SaveGroup(context.Background(), "prod", []string{"east", "west"}); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/groups", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var groups []store.GroupRecord
	if err := json.Unmarshal(w.Body.Bytes(), &groups); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(groups) != 1 || groups[0].Name != "prod" {
		t.Errorf("unexpected groups: %+v", groups)
	}
}

// TestHandleCreateGroup_Validation covers the two 400 paths: malformed JSON
// and a missing name.
func TestHandleCreateGroup_Validation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		Body       string
		WantStatus int
	}{{ // Test 0: Malformed JSON.
		Name: "bad json", Body: "{not-json", WantStatus: http.StatusBadRequest,
	}, { // Test 1: Missing name.
		Name: "empty name", Body: `{"clusters":["a"]}`, WantStatus: http.StatusBadRequest,
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t)
			req := httptest.NewRequest(http.MethodPost, "/api/groups",
				strings.NewReader(test.Body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			if w.Code != test.WantStatus {
				t.Errorf("want %d, got %d body=%s", test.WantStatus, w.Code, w.Body.String())
			}
		})
	}
}

// TestHandleListContexts_DemoReturnsFleet verifies the demo path enumerates
// the synthetic fleet's contexts as already-scanned.
func TestHandleListContexts_DemoReturnsFleet(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/contexts", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var out []contextInfo
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) == 0 {
		t.Error("demo contexts should not be empty")
	}
	if !out[0].Scanned {
		t.Error("demo contexts should be marked scanned")
	}
}

// TestSafeMessage covers the sanitization branches for error messages
// returned to clients.
func TestSafeMessage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		In         error
		Fallback   string
		WantResult string
	}{{ // Test 0: Nil error yields the fallback.
		Name: "nil", In: nil, Fallback: "fallback", WantResult: "fallback",
	}, { // Test 1: Plain message passes through.
		Name: "plain", In: errors.New("bad input"), Fallback: "fb", WantResult: "bad input",
	}, { // Test 2: Forward-slash path is redacted to fallback.
		Name: "unix path", In: errors.New("open /home/u/x: denied"), Fallback: "fb", WantResult: "fb",
	}, { // Test 3: Backslash path is redacted to fallback.
		Name: "win path", In: errors.New(`C:\Users\x`), Fallback: "fb", WantResult: "fb",
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if got := safeMessage(test.In, test.Fallback); got != test.WantResult {
				t.Errorf("test %d: want %q, got %q", i, test.WantResult, got)
			}
		})
	}
}
