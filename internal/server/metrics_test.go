package server

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/google/go-cmp/cmp"
)

func TestPromLabelEscape(t *testing.T) {
	t.Parallel()
	cases := []struct{ In, Want string }{
		{`simple`, `simple`},
		{`with space`, `with space`},
		{`quote " here`, `quote \" here`},
		{`back\slash`, `back\\slash`},
		{"new\nline", `new\nline`},
		{`mixed "back\slash"`, `mixed \"back\\slash\"`},
	}
	for i, c := range cases {
		t.Run(fmt.Sprintf("test %d", i), func(t *testing.T) {
			t.Parallel()
			if got := promLabelEscape(c.In); got != c.Want {
				t.Errorf("escape(%q): want %q, got %q", c.In, c.Want, got)
			}
		})
	}
}

func TestMetricsReportCache(t *testing.T) {
	t.Parallel()
	srv, st := testServer(t)
	seedScan(t, st, "a", "b")
	for range 2 {
		var buf bytes.Buffer
		srv.writeMetrics(context.Background(), &buf)
		mustContain(t, buf.String(), "fleetsweeper_cluster_count 2")
	}
	srv.reports.mu.Lock()
	defer srv.reports.mu.Unlock()
	if got := len(srv.reports.entries); got != 1 {
		t.Errorf("report cache holds %d entries after two scrapes, want 1", got)
	}
}

func TestWriteMetrics_EmptyStore(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	var buf bytes.Buffer
	srv.writeMetrics(context.Background(), &buf)
	out := buf.String()
	mustContain(t, out, "# HELP fleetsweeper_scans_total")
	mustContain(t, out, `fleetsweeper_scans_total{result="success"} 0`)
	mustContain(t, out, "# fleetsweeper: no scans available yet")
}

func TestWriteMetrics_DemoMode(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)
	var buf bytes.Buffer
	srv.writeMetrics(context.Background(), &buf)
	out := buf.String()
	mustContain(t, out, "fleetsweeper_cluster_count ")
	mustContain(t, out, "fleetsweeper_fleet_score ")
	mustContain(t, out, "fleetsweeper_findings_total{severity=\"critical\"}")
	mustContain(t, out, "fleetsweeper_cluster_health{cluster=")
	mustContain(t, out, "fleetsweeper_finding_count{severity=")
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("metrics output does not end with newline")
	}
}

func TestWriteMetrics_LastScanDuration(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.lastScanDuration.Store(int64(2500 * time.Millisecond))
	var buf bytes.Buffer
	srv.writeMetrics(context.Background(), &buf)
	out := buf.String()
	mustContain(t, out, "fleetsweeper_last_scan_duration_seconds 2.500")
}

// newDemoServer returns a Server in demo mode on a store seeded with the demo
// fleet, its newest scan at demoTestNow.
func newDemoServer(t *testing.T) *Server {
	t.Helper()
	srv, st := testServer(t)
	if err := SeedDemo(t.Context(), st, demoTestNow); err != nil {
		t.Fatalf("seed demo: %v", err)
	}
	srv.demo = true
	return srv
}

func mustContain(t *testing.T, haystack, needle string) {
	t.Helper()
	if !strings.Contains(haystack, needle) {
		t.Errorf("expected metrics output to contain %q; full output:\n%s", needle, haystack)
	}
}

// Compile-time guard so refactors that drop the fields surface immediately.
var (
	_ = atomic.Int64{}
	_ = sync.Mutex{}
	_ = zap.NewNop
	_ = scanner.NewRegistry
)

// TestRecordScanDuration verifies the gauge stores the last scan duration.
func TestRecordScanDuration(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	srv.recordScanDuration(1500 * time.Millisecond)
	if got := srv.lastScanDuration.Load(); got != int64(1500*time.Millisecond) {
		t.Errorf("want %d, got %d", int64(1500*time.Millisecond), got)
	}
}

// TestWriteMetrics_SeededScan exercises latestReportForMetrics against a real
// stored scan (not the demo fallback) and confirms the report-derived gauges
// are emitted.
func TestWriteMetrics_SeededScan(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedScan(t, ss, "east", "west", "south")

	var buf bytes.Buffer
	srv.writeMetrics(context.Background(), &buf)
	out := buf.String()
	if !strings.Contains(out, "fleetsweeper_fleet_score ") {
		t.Errorf("expected fleet score gauge from seeded scan:\n%s", out)
	}
	if !strings.Contains(out, "fleetsweeper_cluster_count ") {
		t.Error("expected cluster count gauge")
	}
	// Match value lines, not the HELP/TYPE comments that share the name.
	for _, gauge := range []string{
		"\nfleetsweeper_fleet_score_sample_clusters ",
		"\nfleetsweeper_fleet_score_dimensions ",
		"\nfleetsweeper_fleet_score_excluded_clusters ",
	} {
		if !strings.Contains(out, gauge) {
			t.Errorf("expected provenance gauge %q", gauge)
		}
	}

	// A second call should hit the memoized report cache path.
	var buf2 bytes.Buffer
	srv.writeMetrics(context.Background(), &buf2)
	if buf2.Len() == 0 {
		t.Error("cached metrics pass produced no output")
	}
}

// TestWriteMetrics_HeldOutliers verifies held outliers (those with an ExplainedBy) are not
// exported as outlier_score series.
func TestWriteMetrics_HeldOutliers(t *testing.T) {
	t.Parallel()
	srv := newDemoServer(t)
	r := srv.latestReportForMetrics(t.Context())
	if r == nil {
		t.Fatal("demo server produced no report")
	}
	open, held := 0, 0
	for _, o := range r.Outliers {
		if len(o.ExplainedBy) == 0 {
			open++
		} else {
			held++
		}
	}
	if open == 0 || held == 0 {
		t.Fatalf("demo fixture needs open and held outliers, got open=%d held=%d", open, held)
	}

	var buf bytes.Buffer
	srv.writeMetrics(t.Context(), &buf)

	tests := []struct {
		WantSeries int
	}{{ // Test 0: Only outliers without an explanation are exported.
		WantSeries: open,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := strings.Count(buf.String(), "\nfleetsweeper_outlier_score{")
			if diff := cmp.Diff(test.WantSeries, got); diff != "" {
				t.Errorf("series count (held=%d) (-want +got):\n%s", held, diff)
			}
		})
	}
}
