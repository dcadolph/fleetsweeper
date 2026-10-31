package server

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// seedUngradedScan stores a scan in which every scanner run errored on every cluster.
func seedUngradedScan(t *testing.T, ss *store.SQLite, clusters ...string) string {
	t.Helper()
	results := make(map[string]map[string]scanner.Result, len(clusters))
	for _, c := range clusters {
		results[c] = map[string]scanner.Result{
			"version": scanner.ErroredResult("version", fmt.Errorf("unreachable")),
			"metrics": scanner.ErroredResult("metrics", fmt.Errorf("unreachable")),
		}
	}
	id, err := ss.SaveScan(context.Background(), clusters, results)
	if err != nil {
		t.Fatalf("seed ungraded scan: %v", err)
	}
	return id
}

// TestWriteMetrics_Graded verifies the score series follows the Graded flag and the graded and
// coverage series are always emitted.
func TestWriteMetrics_Graded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Seed          func(*testing.T, *store.SQLite)
		WantScore     bool
		WantGradedOne bool
	}{{ // Test 0: A graded scan emits the score and graded 1.
		Seed:      func(t *testing.T, ss *store.SQLite) { seedScan(t, ss, "east", "west") },
		WantScore: true, WantGradedOne: true,
	}, { // Test 1: An ungraded scan skips the score and emits graded 0.
		Seed: func(t *testing.T, ss *store.SQLite) { seedUngradedScan(t, ss, "east", "west") },
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			srv, ss := testServer(t)
			test.Seed(t, ss)
			var buf bytes.Buffer
			srv.writeMetrics(context.Background(), &buf)
			out := buf.String()
			if got := strings.Contains(out, "\nfleetsweeper_fleet_score "); got != test.WantScore {
				t.Errorf("fleet_score present = %t, want %t:\n%s", got, test.WantScore, out)
			}
			wantGraded := "\nfleetsweeper_fleet_score_graded 0\n"
			if test.WantGradedOne {
				wantGraded = "\nfleetsweeper_fleet_score_graded 1\n"
			}
			mustContain(t, out, wantGraded)
			mustContain(t, out, "\nfleetsweeper_coverage_ratio ")
		})
	}
}

// TestFleetScoreHistory_SkipsUngraded verifies forecast history drops ungraded scans.
func TestFleetScoreHistory_SkipsUngraded(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedScan(t, ss, "east", "west")
	seedUngradedScan(t, ss, "east", "west")
	seedScan(t, ss, "east", "west")

	req := httptest.NewRequest(http.MethodGet, "/api/forecast/fleet-score?scans=5", nil)
	w := httptest.NewRecorder()
	srv.mux.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		History []map[string]any `json:"history"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if diff := cmp.Diff(2, len(resp.History)); diff != "" {
		t.Errorf("history length mismatch (-want +got):\n%s", diff)
	}
}

// TestBuildSlackPayload_Graded verifies the score line follows the Graded flag.
func TestBuildSlackPayload_Graded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Score      report.FleetScore
		WantLine   string
		WantAbsent string
	}{{ // Test 0: A graded fleet shows the score.
		Score:    report.FleetScore{Score: 82, Grade: "B", Graded: true, SampleSize: 2, Dimensions: 3},
		WantLine: "Fleet Score: 82/B",
	}, { // Test 1: An ungraded fleet shows the coverage instead of the score.
		Score: report.FleetScore{
			Score: 100, Coverage: report.FleetCoverage{Fraction: 0.5}, ExcludedClusters: 2,
		},
		WantLine: "Fleet not graded (coverage 50%).", WantAbsent: "Fleet Score:",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			p := buildSlackPayload(nil, &report.Report{FleetScore: test.Score})
			raw, err := json.Marshal(p)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !strings.Contains(string(raw), test.WantLine) {
				t.Errorf("payload missing %q: %s", test.WantLine, raw)
			}
			if test.WantAbsent != "" && strings.Contains(string(raw), test.WantAbsent) {
				t.Errorf("payload contains %q: %s", test.WantAbsent, raw)
			}
		})
	}
}
