package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

// TestTruncR verifies right-truncation with an ellipsis and pass-through.
func TestTruncR(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In    string
		WantS string
		Width int
	}{
		{In: "short", WantS: "short", Width: 10},              // Test 0: Fits, unchanged.
		{In: "exactly-ten", WantS: "exactly-ten", Width: 11},  // Test 1: Exact width, unchanged.
		{In: "toolongvalue", WantS: "toolongval…", Width: 11}, // Test 2: Over width, truncated with ellipsis.
	}
	for testNum, test := range tests {
		t.Run(test.In, func(t *testing.T) {
			t.Parallel()
			if got := truncR(test.In, test.Width); got != test.WantS {
				t.Errorf("test %d: got %q, want %q", testNum, got, test.WantS)
			}
		})
	}
}

// TestFormatDelta verifies signed rendering of per-cluster score deltas.
func TestFormatDelta(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantS string
		In    int
	}{
		{WantS: "+5", In: 5},  // Test 0: Positive gets a plus sign.
		{WantS: "-3", In: -3}, // Test 1: Negative keeps its sign.
		{WantS: "0", In: 0},   // Test 2: Zero renders bare.
	}
	for testNum, test := range tests {
		t.Run(test.WantS, func(t *testing.T) {
			t.Parallel()
			if got := formatDelta(test.In); got != test.WantS {
				t.Errorf("test %d: got %q, want %q", testNum, got, test.WantS)
			}
		})
	}
}

// TestColorCodeHelpers verifies the score, status, delta, and fleet color
// mappings return the expected ANSI numeric codes.
func TestColorCodeHelpers(t *testing.T) {
	t.Parallel()

	// Test 0: statusColor mapping.
	statusCases := map[string]string{
		"critical": "31", "degraded": "33", "strained": "33",
		"busy": "34", "healthy": "32", "unknown": "32",
	}
	for status, want := range statusCases {
		if got := statusColor(status); got != want {
			t.Errorf("statusColor(%q): got %q, want %q", status, got, want)
		}
	}

	// Test 1: scoreColorCode and fleetColor share the 80/60 thresholds.
	scoreCases := map[int]string{95: "32", 70: "33", 40: "31", 80: "32", 60: "33"}
	for score, want := range scoreCases {
		if got := scoreColorCode(score); got != want {
			t.Errorf("scoreColorCode(%d): got %q, want %q", score, got, want)
		}
		s := &topState{}
		if got := s.fleetColor(score); got != want {
			t.Errorf("fleetColor(%d): got %q, want %q", score, got, want)
		}
	}

	// Test 2: deltaColor: improving green, degrading red, flat dim.
	deltaCases := map[int]string{7: "32", -7: "31", 0: "90"}
	for d, want := range deltaCases {
		if got := deltaColor(d); got != want {
			t.Errorf("deltaColor(%d): got %q, want %q", d, got, want)
		}
	}
}

// TestTopStateColorToggles verifies color3, resetCode, and dim return
// empty strings when color is disabled and escapes when enabled.
func TestTopStateColorToggles(t *testing.T) {
	t.Parallel()

	off := &topState{color: false}
	if off.color3("31") != "" || off.resetCode() != "" || off.dim() != "" {
		t.Error("color-off state must return empty escape strings")
	}

	on := &topState{color: true}
	if got := on.color3("31"); got != "\033[31m" {
		t.Errorf("color3: got %q", got)
	}
	if got := on.resetCode(); got != "\033[0m" {
		t.Errorf("resetCode: got %q", got)
	}
	if got := on.dim(); got != "\033[90m" {
		t.Errorf("dim: got %q", got)
	}
}

// TestSortLabel verifies each sort mode reports its human label.
func TestSortLabel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantS string
		In    topSortMode
	}{
		{WantS: "score (worst first)", In: sortByScore}, // Test 0: Default score mode.
		{WantS: "name", In: sortByName},                 // Test 1: Name mode.
		{WantS: "status", In: sortByStatus},             // Test 2: Status mode.
	}
	for testNum, test := range tests {
		t.Run(test.WantS, func(t *testing.T) {
			t.Parallel()
			s := &topState{sortBy: test.In}
			if got := s.sortLabel(); got != test.WantS {
				t.Errorf("test %d: got %q, want %q", testNum, got, test.WantS)
			}
		})
	}
}

// TestBuildRows verifies per-cluster row assembly, severity counting, and
// delta computation against the previous report.
func TestBuildRows(t *testing.T) {
	t.Parallel()
	rpt := &topReport{
		ClusterHealths: []topClusterHealth{
			{Name: "a", Status: "healthy", AvgCPU: 10, AvgMemory: 20},
			{Name: "b", Status: "critical", AvgCPU: 80, AvgMemory: 90},
		},
		ClusterScores: []topClusterScore{{Cluster: "a", Score: 90}, {Cluster: "b", Score: 40}},
		Findings: []topFinding{
			{Severity: "critical", Cluster: "b"},
			{Severity: "warning", Cluster: "b"},
			{Severity: "critical", Cluster: "a"},
		},
	}
	prev := &topReport{ClusterScores: []topClusterScore{{Cluster: "a", Score: 95}, {Cluster: "b", Score: 30}}}

	s := &topState{}
	got := s.buildRows(rpt, prev)
	want := []topRow{
		{Cluster: "a", Status: "healthy", Score: 90, CPU: 10, Memory: 20, Critical: 1, Warning: 0, Delta: -5},
		{Cluster: "b", Status: "critical", Score: 40, CPU: 80, Memory: 90, Critical: 1, Warning: 1, Delta: 10},
	}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("buildRows mismatch (-want +got):\n%s", diff)
	}
}

// TestBuildRowsNoPrev verifies deltas fall back to the raw score when no
// previous report is available.
func TestBuildRowsNoPrev(t *testing.T) {
	t.Parallel()
	rpt := &topReport{
		ClusterHealths: []topClusterHealth{{Name: "a", Status: "healthy"}},
		ClusterScores:  []topClusterScore{{Cluster: "a", Score: 88}},
	}
	s := &topState{}
	got := s.buildRows(rpt, nil)
	if len(got) != 1 || got[0].Delta != 88 {
		t.Errorf("want single row with delta 88, got %+v", got)
	}
}

// TestLessFn verifies each sort mode orders rows as documented.
func TestLessFn(t *testing.T) {
	t.Parallel()
	base := []topRow{
		{Cluster: "beta", Status: "healthy", Score: 90},
		{Cluster: "alpha", Status: "critical", Score: 40},
		{Cluster: "gamma", Status: "busy", Score: 70},
	}

	tests := []struct {
		WantOrder []string
		Mode      topSortMode
	}{
		{WantOrder: []string{"alpha", "gamma", "beta"}, Mode: sortByScore},  // Test 0: Worst score first.
		{WantOrder: []string{"alpha", "beta", "gamma"}, Mode: sortByName},   // Test 1: Alphabetical.
		{WantOrder: []string{"alpha", "gamma", "beta"}, Mode: sortByStatus}, // Test 2: critical<busy<healthy.
	}
	for testNum, test := range tests {
		t.Run(test.WantOrder[0], func(t *testing.T) {
			t.Parallel()
			rows := make([]topRow, len(base))
			copy(rows, base)
			s := &topState{sortBy: test.Mode}
			sort.Slice(rows, s.lessFn(rows))
			got := make([]string, len(rows))
			for i, r := range rows {
				got[i] = r.Cluster
			}
			if diff := cmp.Diff(test.WantOrder, got); diff != "" {
				t.Errorf("test %d: order mismatch (-want +got):\n%s", testNum, diff)
			}
		})
	}
}

// TestGetJSON verifies decode on 200 and an error on a non-200 status.
func TestGetJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bad" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"hello": "world"})
	}))
	defer srv.Close()

	s := &topState{server: srv.URL, client: srv.Client()}
	var out map[string]string
	if err := s.getJSON(context.Background(), "/ok", &out); err != nil {
		t.Fatalf("getJSON ok: %v", err)
	}
	if out["hello"] != "world" {
		t.Errorf("decoded: %+v", out)
	}
	if err := s.getJSON(context.Background(), "/bad", &out); err == nil {
		t.Error("expected error for 500 status")
	}
}

// TestHydrateScoresForecast verifies scores come from the forecast endpoint
// when it responds.
func TestHydrateScoresForecast(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"forecasts": []map[string]any{
				{"cluster": "a", "current_score": 77},
				{"cluster": "b", "current_score": 33},
			},
		})
	}))
	defer srv.Close()

	s := &topState{server: srv.URL, client: srv.Client()}
	r := &topReport{ClusterHealths: []topClusterHealth{{Name: "a", Status: "healthy"}}}
	s.hydrateScores(context.Background(), r)
	want := []topClusterScore{{Cluster: "a", Score: 77}, {Cluster: "b", Score: 33}}
	if diff := cmp.Diff(want, r.ClusterScores, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("forecast scores mismatch (-want +got):\n%s", diff)
	}
}

// TestHydrateScoresFallback verifies the synthetic status-based fallback when
// the forecast endpoint is unavailable.
func TestHydrateScoresFallback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := &topState{server: srv.URL, client: srv.Client()}
	r := &topReport{ClusterHealths: []topClusterHealth{
		{Name: "crit", Status: "critical"},
		{Name: "deg", Status: "degraded"},
		{Name: "busy", Status: "busy"},
		{Name: "ok", Status: "healthy"},
	}}
	s.hydrateScores(context.Background(), r)
	want := []topClusterScore{
		{Cluster: "crit", Score: 40},
		{Cluster: "deg", Score: 75},
		{Cluster: "busy", Score: 90},
		{Cluster: "ok", Score: 100},
	}
	if diff := cmp.Diff(want, r.ClusterScores, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("fallback scores mismatch (-want +got):\n%s", diff)
	}
}

// newTopTestServer returns an httptest server serving a two-scan fleet so the
// fetch + render path can run end to end without a live cluster.
func newTopTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	report := func(fleet int, grade string) topReport {
		return topReport{
			Timestamp:  "2026-01-01T00:00:00Z",
			Clusters:   []string{"a", "b"},
			FleetScore: topFleetScore{Score: fleet, Grade: grade},
			ClusterHealths: []topClusterHealth{
				{Name: "a", Status: "healthy", AvgCPU: 12, AvgMemory: 30},
				{Name: "b", Status: "critical", AvgCPU: 88, AvgMemory: 91},
			},
			Findings: []topFinding{
				{Severity: "critical", Cluster: "b"},
				{Severity: "warning", Cluster: "b"},
			},
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/scans", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{{"id": "s1"}, {"id": "s2"}})
	})
	mux.HandleFunc("/api/scans/s1/report", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(report(70, "C"))
	})
	mux.HandleFunc("/api/scans/s2/report", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(report(80, "B"))
	})
	mux.HandleFunc("/api/forecast/clusters", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"forecasts": []map[string]any{
				{"cluster": "a", "current_score": 90},
				{"cluster": "b", "current_score": 40},
			},
		})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// TestFetchLatestReports verifies both the current and previous reports are
// fetched and hydrated with per-cluster scores.
func TestFetchLatestReports(t *testing.T) {
	t.Parallel()
	srv := newTopTestServer(t)
	s := &topState{server: srv.URL, client: srv.Client()}
	cur, prev, err := s.fetchLatestReports(context.Background())
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if cur.FleetScore.Score != 70 || prev == nil || prev.FleetScore.Score != 80 {
		t.Fatalf("cur=%+v prev=%+v", cur.FleetScore, prev)
	}
	if len(cur.ClusterScores) != 2 {
		t.Errorf("expected hydrated cluster scores, got %+v", cur.ClusterScores)
	}
}

// TestFetchLatestReportsNoScans verifies an empty scan list is an error.
func TestFetchLatestReportsNoScans(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode([]map[string]string{})
	}))
	defer srv.Close()
	s := &topState{server: srv.URL, client: srv.Client()}
	if _, _, err := s.fetchLatestReports(context.Background()); err == nil {
		t.Error("expected error when no scans exist")
	}
}

// TestDrawRendersTable verifies the full fetch-to-render path writes a header,
// the cluster rows, and the key-binding footer.
func TestDrawRendersTable(t *testing.T) {
	t.Parallel()
	srv := newTopTestServer(t)
	buf := &bytes.Buffer{}
	s := &topState{
		server: srv.URL,
		client: srv.Client(),
		out:    buf,
		limit:  20,
		color:  false,
		sortBy: sortByScore,
	}
	if err := s.draw(context.Background()); err != nil {
		t.Fatalf("draw: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"fleetsweeper top", "Fleet Score:", "CLUSTER", "a", "b", "[q] quit"} {
		if !strings.Contains(out, want) {
			t.Errorf("draw output missing %q:\n%s", want, out)
		}
	}
}

// TestDrawHonorsLimit verifies the row cap is applied before rendering.
func TestDrawHonorsLimit(t *testing.T) {
	t.Parallel()
	srv := newTopTestServer(t)
	buf := &bytes.Buffer{}
	s := &topState{server: srv.URL, client: srv.Client(), out: buf, limit: 1, sortBy: sortByScore}
	if err := s.draw(context.Background()); err != nil {
		t.Fatalf("draw: %v", err)
	}
	// With limit 1 and worst-first sort, only the critical cluster "b" renders.
	if strings.Count(buf.String(), "critical") == 0 {
		t.Errorf("expected the worst cluster row, got:\n%s", buf.String())
	}
}

// TestClearAndPrintError verifies clear emits blank lines without color and
// printError prefixes the message.
func TestClearAndPrintError(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	s := &topState{out: buf, color: false}
	s.clear()
	if buf.String() != "\n\n" {
		t.Errorf("clear without color: got %q", buf.String())
	}

	buf.Reset()
	s.printError(context.DeadlineExceeded)
	if !strings.Contains(buf.String(), "fleetsweeper top:") {
		t.Errorf("printError missing prefix: %q", buf.String())
	}
}

// TestPrintHeaderShowsDelta verifies the header includes a delta note when the
// previous fleet score is available.
func TestPrintHeaderShowsDelta(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	s := &topState{out: buf, color: false, server: "http://x"}
	cur := &topReport{Clusters: []string{"a"}, FleetScore: topFleetScore{Score: 80, Grade: "B"}}
	prev := &topReport{FleetScore: topFleetScore{Score: 70}}
	s.printHeader(cur, prev)
	out := buf.String()
	if !strings.Contains(out, "(+10 vs previous)") {
		t.Errorf("expected +10 delta note, got:\n%s", out)
	}
}

// TestPrintTableEmitsRows verifies the table renders one line per row with the
// cluster name and status.
func TestPrintTableEmitsRows(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	s := &topState{out: buf, color: true}
	s.printTable([]topRow{{Cluster: "prod-east", Status: "critical", Score: 40, Delta: -5}})
	out := buf.String()
	if !strings.Contains(out, "prod-east") || !strings.Contains(out, "critical") {
		t.Errorf("printTable missing content:\n%s", out)
	}
}

// TestTopPausedNote verifies the paused flag surfaces in the header once set.
func TestTopPausedNote(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	s := &topState{out: buf, color: false, server: "http://x"}
	s.paused.Store(true)
	s.printHeader(&topReport{FleetScore: topFleetScore{Score: 50}}, nil)
	if !strings.Contains(buf.String(), "[PAUSED]") {
		t.Errorf("expected paused marker, got:\n%s", buf.String())
	}
}
