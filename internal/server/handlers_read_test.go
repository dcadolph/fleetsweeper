package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/dcadolph/fleetsweeper/internal/report"
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

// TestHandleGetScan_DemoRecord verifies demo mode serves the newest seeded
// demo scan record by its ID.
func TestHandleGetScan_DemoRecord(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/scans/"+demoScanIDAt(demoScans-1), nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if decodeObj(t, w)["id"] != demoScanIDAt(demoScans-1) {
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

// TestHandleGetScanReport_DegradedSurvivesStore verifies a scanner that
// errored during a stored scan is listed as degraded in the rebuilt report,
// exactly as the live scan reported it, rather than read as a clean result.
func TestHandleGetScanReport_DegradedSurvivesStore(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	clusters := []string{"east", "west"}
	results := make(map[string]map[string]scanner.Result, len(clusters))
	for _, c := range clusters {
		results[c] = map[string]scanner.Result{
			"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2", "minor": 31}},
		}
	}
	results["west"]["certs"] = scanner.ErroredResult("certs", errors.New("context deadline exceeded"))
	id, err := ss.SaveScan(context.Background(), clusters, results)
	if err != nil {
		t.Fatalf("seed scan: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/scans/"+id+"/report", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got struct {
		Degraded []report.ScannerStatus `json:"degraded"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode report: %v", err)
	}
	want := []report.ScannerStatus{{
		Cluster: "west", Scanner: "certs", State: "errored", Reason: "context deadline exceeded",
	}}
	if diff := cmp.Diff(want, got.Degraded); diff != "" {
		t.Errorf("degraded mismatch (-want +got):\n%s", diff)
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

// TestHandleListContexts_DemoListsNone verifies the demo offers no kubeconfig
// contexts, so it never reaches a real cluster.
func TestHandleListContexts_DemoListsNone(t *testing.T) {
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
	if len(out) != 0 {
		t.Errorf("demo listed %d contexts, want none", len(out))
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

// TestQueryLimit covers defaulting, rejection of non-positive values, and the ceiling.
func TestQueryLimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Query      string
		WantResult int
	}{{ // Test 0: Absent uses the default.
		Query: "", WantResult: 10,
	}, { // Test 1: A value inside the range is used as is.
		Query: "n=42", WantResult: 42,
	}, { // Test 2: The ceiling itself is allowed.
		Query: "n=100", WantResult: 100,
	}, { // Test 3: One over the ceiling is capped.
		Query: "n=101", WantResult: 100,
	}, { // Test 4: A huge value is capped.
		Query: "n=99999999", WantResult: 100,
	}, { // Test 5: Zero uses the default.
		Query: "n=0", WantResult: 10,
	}, { // Test 6: A negative value uses the default.
		Query: "n=-5", WantResult: 10,
	}, { // Test 7: A non-integer uses the default.
		Query: "n=ten", WantResult: 10,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, "/?"+test.Query, nil)
			if got := queryLimit(req, "n", 10, 100); got != test.WantResult {
				t.Errorf("want %d, got %d", test.WantResult, got)
			}
		})
	}
}

// TestScanWindowCaps verifies /scans?limit= and the trend endpoints' ?scans= never load more
// than maxScanWindow scans, however large the request.
func TestScanWindowCaps(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	for i := range maxScanWindow + 5 {
		c := fmt.Sprintf("c-%d", i)
		if _, err := ss.SaveScan(ctx, []string{c}, map[string]map[string]scanner.Result{
			c: {"version": {Scanner: "version", Data: map[string]any{"minor": 31}}},
		}); err != nil {
			t.Fatalf("seed scan %d: %v", i, err)
		}
	}
	counter := &countingStore{Store: ss}
	srv.store = counter

	tests := []struct {
		Path      string
		WantLimit int
	}{{ // Test 0: List scans with a huge limit.
		Path: "/api/scans?limit=100000", WantLimit: maxScanWindow,
	}, { // Test 1: List scans with no limit uses the default.
		Path: "/api/scans", WantLimit: 50,
	}, { // Test 2: Fleet trends with a huge window.
		Path: "/api/trends?scans=100000", WantLimit: maxScanWindow,
	}, { // Test 3: Cluster trends with a huge window.
		Path: "/api/trends/c-1?scans=100000", WantLimit: maxScanWindow,
	}}
	for testNum, test := range tests {
		req := httptest.NewRequest(http.MethodGet, test.Path, nil)
		w := httptest.NewRecorder()
		srv.mux.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("test %d: want 200, got %d body=%.200s", testNum, w.Code, w.Body.String())
		}
		if got := counter.lastLimit.Load(); int(got) != test.WantLimit {
			t.Errorf("test %d: want ListScans limit %d, got %d", testNum, test.WantLimit, got)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/scans?limit=100000", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	var scans []store.ScanRecord
	if err := json.Unmarshal(w.Body.Bytes(), &scans); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(scans) != maxScanWindow {
		t.Errorf("want %d scans returned, got %d", maxScanWindow, len(scans))
	}
}

// countingStore records the limit of the most recent ListScans call.
type countingStore struct {
	store.Store
	// lastLimit is the limit passed to the most recent ListScans call.
	lastLimit atomic.Int64
}

// ListScans records limit and delegates to the wrapped store.
func (c *countingStore) ListScans(ctx context.Context, limit int) ([]store.ScanRecord, error) {
	c.lastLimit.Store(int64(limit))
	return c.Store.ListScans(ctx, limit)
}

// TestStoreErrorsAre500 verifies a failing store yields a logged 500 rather than a 404, an empty
// list, or demo data, while a genuinely missing record still yields 404.
func TestStoreErrorsAre500(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Method string
		Path   string
		Body   string
	}{{ // Test 0: Get scan.
		Method: http.MethodGet, Path: "/api/scans/s-1",
	}, { // Test 1: Get scan report.
		Method: http.MethodGet, Path: "/api/scans/s-1/report",
	}, { // Test 2: List clusters.
		Method: http.MethodGet, Path: "/api/clusters",
	}, { // Test 3: Cluster detail.
		Method: http.MethodGet, Path: "/api/clusters/east/detail",
	}, { // Test 4: Fleet trends.
		Method: http.MethodGet, Path: "/api/trends",
	}, { // Test 5: Cluster trends.
		Method: http.MethodGet, Path: "/api/trends/east",
	}, { // Test 6: Outliers.
		Method: http.MethodGet, Path: "/api/outliers",
	}, { // Test 7: Cohorts.
		Method: http.MethodGet, Path: "/api/cohorts",
	}, { // Test 8: Capacity.
		Method: http.MethodGet, Path: "/api/capacity",
	}, { // Test 9: Geo.
		Method: http.MethodGet, Path: "/api/geo",
	}, { // Test 10: Delete group.
		Method: http.MethodDelete, Path: "/api/groups/prod",
	}, { // Test 11: Ack an alert.
		Method: http.MethodPost, Path: "/api/alerts/fp-1/ack", Body: `{"reason":"known"}`,
	}, { // Test 12: Trigger a scan of a group.
		Method: http.MethodPost, Path: "/api/scans", Body: `{"group":"prod"}`,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t)
			srv.demo = true
			core, logs := observer.New(zap.ErrorLevel)
			srv.log = zap.New(core)
			srv.store = brokenStore{Store: srv.store}

			req := httptest.NewRequest(test.Method, test.Path, strings.NewReader(test.Body))
			w := httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			if w.Code != http.StatusInternalServerError {
				t.Errorf("want 500, got %d body=%.200s", w.Code, w.Body.String())
			}
			if logs.Len() == 0 {
				t.Error("want an error log line, got none")
			}
		})
	}
}

// TestMissingRecordsAre404 verifies not-found store results still map to 404.
func TestMissingRecordsAre404(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Method string
		Path   string
	}{{ // Test 0: Unknown scan.
		Method: http.MethodGet, Path: "/api/scans/nope",
	}, { // Test 1: Unknown scan report.
		Method: http.MethodGet, Path: "/api/scans/nope/report",
	}, { // Test 2: Unknown group.
		Method: http.MethodDelete, Path: "/api/groups/nope",
	}, { // Test 3: Unknown alert.
		Method: http.MethodPost, Path: "/api/alerts/nope/ack",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t)
			req := httptest.NewRequest(test.Method, test.Path, nil)
			w := httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			if w.Code != http.StatusNotFound {
				t.Errorf("want 404, got %d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

// errBrokenStore is the failure every brokenStore read returns.
var errBrokenStore = errors.New("disk on fire")

// brokenStore fails every read and group delete the handlers under test make, while audit
// writes still succeed so the request reaches its handler.
type brokenStore struct {
	store.Store
}

// GetScan fails.
func (brokenStore) GetScan(context.Context, string) (*store.ScanRecord, error) {
	return nil, errBrokenStore
}

// ListScans fails.
func (brokenStore) ListScans(context.Context, int) ([]store.ScanRecord, error) {
	return nil, errBrokenStore
}

// ListClusters fails.
func (brokenStore) ListClusters(context.Context) ([]store.ClusterRecord, error) {
	return nil, errBrokenStore
}

// GetGroup fails.
func (brokenStore) GetGroup(context.Context, string) (*store.GroupRecord, error) {
	return nil, errBrokenStore
}

// DeleteGroup fails.
func (brokenStore) DeleteGroup(context.Context, string) error {
	return errBrokenStore
}

// GetAlert fails.
func (brokenStore) GetAlert(context.Context, string) (*store.AlertRecord, error) {
	return nil, errBrokenStore
}

// TestListScanners verifies GET /api/scanners returns the full catalog
// through the served handler.
func TestListScanners(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/scanners", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var got []report.ScannerInfo
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if diff := cmp.Diff(report.ScannerCatalog(), got); diff != "" {
		t.Errorf("catalog mismatch (-want +got):\n%s", diff)
	}
}
