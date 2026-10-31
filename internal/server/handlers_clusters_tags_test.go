package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestListClusters_IncludesTags verifies the augmented handler folds
// the cluster_tags rows into each ClusterRecord on the wire.
func TestListClusters_IncludesTags(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	if _, err := ss.SaveScan(ctx, []string{"east", "west"}, map[string]map[string]scanner.Result{
		"east": {"version": {Scanner: "version", Data: map[string]any{"v": "1"}}},
		"west": {"version": {Scanner: "version", Data: map[string]any{"v": "1"}}},
	}); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	_ = ss.SetClusterTag(ctx, "east", "env", "prod")
	_ = ss.SetClusterTag(ctx, "east", "tier", "critical")

	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	w := httptest.NewRecorder()
	srv.handleListClusters(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var got []store.ClusterRecord
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byName := map[string]store.ClusterRecord{}
	for _, c := range got {
		byName[c.Name] = c
	}
	if byName["east"].Tags["env"] != "prod" || byName["east"].Tags["tier"] != "critical" {
		t.Errorf("east tags missing: %+v", byName["east"])
	}
	if len(byName["west"].Tags) != 0 {
		t.Errorf("west should have no tags: %+v", byName["west"])
	}
}

// TestJSONBodyLimits verifies every JSON write endpoint rejects an oversized body with 413 and
// a body carrying an unknown field with 400, so no handler reads an unbounded request.
func TestJSONBodyLimits(t *testing.T) {
	t.Parallel()
	huge := `{"name":"` + strings.Repeat("a", 2<<20) + `"}`
	eastFP := report.FindingFingerprint(report.Finding{
		Cluster: "east", Scanner: "workload-security", Rule: "workload-security/privileged",
	})
	tests := []struct {
		Method string
		Path   string
	}{{ // Test 0: Trigger scan.
		Method: http.MethodPost, Path: "/api/scans",
	}, { // Test 1: Create group.
		Method: http.MethodPost, Path: "/api/groups",
	}, { // Test 2: Set cluster tag.
		Method: http.MethodPut, Path: "/api/clusters/east/tags/env",
	}, { // Test 3: Set location.
		Method: http.MethodPut, Path: "/api/locations/east",
	}, { // Test 4: Ack a finding.
		Method: http.MethodPost, Path: "/api/findings/" + eastFP + "/ack",
	}, { // Test 5: Ack an alert.
		Method: http.MethodPost, Path: "/api/alerts/fp-1/ack",
	}, { // Test 6: Create an API key.
		Method: http.MethodPost, Path: "/api/admin/keys",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			srv, ss := testServer(t)
			if err := ss.UpsertAlert(context.Background(), store.AlertRecord{
				Fingerprint: "fp-1", Cluster: "east", Status: "firing", AlertName: "Down",
			}); err != nil {
				t.Fatalf("seed alert: %v", err)
			}
			seedAckFindings(t, srv, ss)

			req := httptest.NewRequest(test.Method, test.Path, strings.NewReader(huge))
			w := httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			if w.Code != http.StatusRequestEntityTooLarge {
				t.Errorf("2 MB body: want 413, got %d body=%.200s", w.Code, w.Body.String())
			}

			req = httptest.NewRequest(test.Method, test.Path, strings.NewReader(`{"not_a_field":1}`))
			w = httptest.NewRecorder()
			srv.mux.ServeHTTP(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("unknown field: want 400, got %d body=%s", w.Code, w.Body.String())
			}
			if !strings.Contains(w.Body.String(), "not_a_field") {
				t.Errorf("unknown field: error should name the field, got %s", w.Body.String())
			}
		})
	}
}

// TestDecodeJSON covers each rejection decodeJSON makes and the status it writes.
func TestDecodeJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Body       string
		WantStatus int
		WantName   string
		Want       bool
	}{{ // Test 0: A well-formed body decodes.
		Body: `{"name":"prod"}`, WantName: "prod",
	}, { // Test 1: Surrounding whitespace is accepted.
		Body: " \n{\"name\":\"prod\"}\n ", WantName: "prod",
	}, { // Test 2: An empty body is rejected.
		Body: "", WantStatus: http.StatusBadRequest, Want: true,
	}, { // Test 3: Malformed JSON is rejected.
		Body: `{"name":`, WantStatus: http.StatusBadRequest, Want: true,
	}, { // Test 4: Unknown fields are rejected.
		Body: `{"name":"prod","extra":true}`, WantStatus: http.StatusBadRequest, Want: true,
	}, { // Test 5: A second JSON value after the first is rejected.
		Body: `{"name":"prod"}{"name":"other"}`, WantStatus: http.StatusBadRequest, Want: true,
	}, { // Test 6: Trailing garbage is rejected.
		Body: `{"name":"prod"} x`, WantStatus: http.StatusBadRequest, Want: true,
	}, { // Test 7: A body exactly at the limit decodes.
		Body: `{"name":"` + strings.Repeat("a", 64) + `"}`, WantName: strings.Repeat("a", 64),
	}, { // Test 8: A body one byte over the limit is rejected as too large.
		Body: `{"name":"` + strings.Repeat("a", 65) + `"}`, WantStatus: http.StatusRequestEntityTooLarge, Want: true,
	}, { // Test 9: A valid value followed by padding past the limit is too large.
		Body: `{"name":"p"}` + strings.Repeat(" ", 80), WantStatus: http.StatusRequestEntityTooLarge, Want: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(test.Body))
			w := httptest.NewRecorder()
			var got createGroupRequest
			err := decodeJSON(w, req, &got, 75)
			if (err != nil) != test.Want {
				t.Fatalf("want error %v, got %v", test.Want, err)
			}
			if test.Want {
				if w.Code != test.WantStatus {
					t.Errorf("want status %d, got %d body=%s", test.WantStatus, w.Code, w.Body.String())
				}
				return
			}
			if w.Body.Len() != 0 {
				t.Errorf("success wrote a response: %s", w.Body.String())
			}
			if got.Name != test.WantName {
				t.Errorf("want name %q, got %q", test.WantName, got.Name)
			}
		})
	}
}
