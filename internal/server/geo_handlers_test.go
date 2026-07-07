package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// seedGeoScan writes a scan where one cluster carries an auto-detected geo
// scanner result and returns the scan ID. The second cluster has no geo
// data so it lands in the unlocated bucket.
func seedGeoScan(t *testing.T, ss *store.SQLite) string {
	t.Helper()
	results := map[string]map[string]scanner.Result{
		"cloud-1": {
			"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.0"}},
			"geo": {Scanner: "geo", Data: map[string]any{
				"has_location": true,
				"provider":     "aws",
				"region":       "us-east-1",
				"city":         "N. Virginia",
				"source":       "annotation",
				"lat":          38.95,
				"lng":          -77.45,
			}},
		},
		"dark-1": {
			"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.0"}},
		},
	}
	id, err := ss.SaveScan(context.Background(), []string{"cloud-1", "dark-1"}, results)
	if err != nil {
		t.Fatalf("seed geo scan: %v", err)
	}
	return id
}

// TestHandleGetGeo_Seeded verifies the geo handler merges auto-detected
// locations, surfaces unlocated clusters, and honors a manual override.
func TestHandleGetGeo_Seeded(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedGeoScan(t, ss)
	// Manual override for the otherwise-unlocated cluster.
	if err := ss.SetLocation(context.Background(), store.LocationRecord{
		Cluster: "dark-1", Lat: 51.5, Lng: -0.12, Site: "London DC",
	}); err != nil {
		t.Fatalf("seed location: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/geo", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}

	var resp struct {
		Points []geoPoint `json:"points"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byCluster := map[string]geoPoint{}
	for _, p := range resp.Points {
		byCluster[p.Cluster] = p
	}
	if got := byCluster["cloud-1"]; got.Source != "annotation" || got.Region != "us-east-1" {
		t.Errorf("auto point wrong: %+v", got)
	}
	if got := byCluster["dark-1"]; got.Source != "manual" || got.Site != "London DC" {
		t.Errorf("manual override not applied: %+v", got)
	}
}

// TestHandleGetGeo_NoScans verifies the non-demo empty-store 404 path.
func TestHandleGetGeo_NoScans(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/geo", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("want 404, got %d", w.Code)
	}
}

// TestExtractAutoGeo covers the geo scanner decode branches.
func TestExtractAutoGeo(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name    string
		Results map[string]map[string]scanner.Result
		Cluster string
		WantNil bool
		WantSrc string
		WantLat float64
	}{{ // Test 0: Cluster absent.
		Name: "no cluster", Results: map[string]map[string]scanner.Result{}, Cluster: "x", WantNil: true,
	}, { // Test 1: No geo scanner.
		Name:    "no geo scanner",
		Results: map[string]map[string]scanner.Result{"x": {"version": {Scanner: "version"}}},
		Cluster: "x", WantNil: true,
	}, { // Test 2: Geo present but has_location false.
		Name: "no location",
		Results: map[string]map[string]scanner.Result{"x": {"geo": {Scanner: "geo",
			Data: map[string]any{"has_location": false}}}},
		Cluster: "x", WantNil: true,
	}, { // Test 3: Located, source defaults to auto when blank.
		Name: "located default source",
		Results: map[string]map[string]scanner.Result{"x": {"geo": {Scanner: "geo",
			Data: map[string]any{"has_location": true, "lat": 10.0, "lng": 20.0}}}},
		Cluster: "x", WantNil: false, WantSrc: "auto", WantLat: 10.0,
	}, { // Test 4: Located with explicit source.
		Name: "located explicit source",
		Results: map[string]map[string]scanner.Result{"x": {"geo": {Scanner: "geo",
			Data: map[string]any{"has_location": true, "source": "configmap", "lat": 1.5, "lng": 2.5}}}},
		Cluster: "x", WantNil: false, WantSrc: "configmap", WantLat: 1.5,
	}}
	for i, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got := extractAutoGeo(test.Results, test.Cluster)
			if test.WantNil {
				if got != nil {
					t.Errorf("test %d: want nil, got %+v", i, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("test %d: want non-nil", i)
			}
			if got.Source != test.WantSrc {
				t.Errorf("test %d: source want %q, got %q", i, test.WantSrc, got.Source)
			}
			if got.Lat != test.WantLat {
				t.Errorf("test %d: lat want %v, got %v", i, test.WantLat, got.Lat)
			}
		})
	}
}

// TestHandleListLocations_Seeded verifies stored overrides are returned.
func TestHandleListLocations_Seeded(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	if err := ss.SetLocation(context.Background(), store.LocationRecord{
		Cluster: "store-1", Lat: 40.7, Lng: -74.0, Site: "NYC",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/locations", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var locs []store.LocationRecord
	if err := json.Unmarshal(w.Body.Bytes(), &locs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(locs) != 1 || locs[0].Cluster != "store-1" {
		t.Errorf("unexpected locations: %+v", locs)
	}
}

// TestHandleSetLocation_Happy verifies a valid override is persisted and the
// handler echoes a saved message.
func TestHandleSetLocation_Happy(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	req := httptest.NewRequest(http.MethodPut, "/api/locations/store-1",
		strings.NewReader(`{"lat":40.71,"lng":-74.01,"site":"NYC"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	locs, err := ss.ListLocations(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(locs) != 1 || locs[0].Site != "NYC" {
		t.Errorf("location not persisted: %+v", locs)
	}
}

// TestHandleSetLocation_Validation covers the 400 branches for malformed
// JSON and out-of-range coordinates.
func TestHandleSetLocation_Validation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name       string
		Body       string
		WantStatus int
	}{{ // Test 0: Malformed JSON.
		Name: "bad json", Body: "{", WantStatus: http.StatusBadRequest,
	}, { // Test 1: Latitude out of range.
		Name: "bad lat", Body: `{"lat":95,"lng":0}`, WantStatus: http.StatusBadRequest,
	}, { // Test 2: Longitude out of range.
		Name: "bad lng", Body: `{"lat":0,"lng":181}`, WantStatus: http.StatusBadRequest,
	}}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			srv, _ := testServer(t)
			req := httptest.NewRequest(http.MethodPut, "/api/locations/store-1",
				strings.NewReader(test.Body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			if w.Code != test.WantStatus {
				t.Errorf("want %d, got %d", test.WantStatus, w.Code)
			}
		})
	}
}

// TestHandleSetLocation_ScopeRejected verifies a scoped actor cannot set a
// location on a cluster outside its scope.
func TestHandleSetLocation_ScopeRejected(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodPut, "/api/locations/east",
		strings.NewReader(`{"lat":1,"lng":2}`))
	req.SetPathValue("cluster", "east")
	scoped := &Actor{ID: "s", Role: store.RoleOperator, ClusterScope: []string{"west"}}
	req = req.WithContext(withActor(req.Context(), scoped))
	w := httptest.NewRecorder()
	srv.handleSetLocation(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("want 403, got %d", w.Code)
	}
}

// TestHandleDeleteLocation covers the happy delete and the scope-rejection
// branch.
func TestHandleDeleteLocation(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	if err := ss.SetLocation(context.Background(), store.LocationRecord{
		Cluster: "east", Lat: 1, Lng: 2,
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	del := httptest.NewRequest(http.MethodDelete, "/api/locations/east", nil)
	dw := httptest.NewRecorder()
	srv.mux.ServeHTTP(dw, del)
	if dw.Code != http.StatusNoContent {
		t.Fatalf("delete: want 204, got %d", dw.Code)
	}
	locs, _ := ss.ListLocations(context.Background())
	if len(locs) != 0 {
		t.Errorf("expected empty after delete, got %+v", locs)
	}

	scopedReq := httptest.NewRequest(http.MethodDelete, "/api/locations/east", nil)
	scopedReq.SetPathValue("cluster", "east")
	scoped := &Actor{ID: "s", Role: store.RoleOperator, ClusterScope: []string{"west"}}
	scopedReq = scopedReq.WithContext(withActor(scopedReq.Context(), scoped))
	sw := httptest.NewRecorder()
	srv.handleDeleteLocation(sw, scopedReq)
	if sw.Code != http.StatusForbidden {
		t.Errorf("scoped delete: want 403, got %d", sw.Code)
	}
}
