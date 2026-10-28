package server

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

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

// TestHandleAckAlert_BadSnooze verifies a malformed snooze timestamp is
// rejected with 400 even when the alert and actor are valid.
func TestHandleAckAlert_BadSnooze(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	if err := ss.UpsertAlert(context.Background(), store.AlertRecord{
		Fingerprint: "fp-snooze", Cluster: "fleet", Status: "firing",
		AlertName: "X", Labels: map[string]string{}, Annotations: map[string]string{},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/alerts/fp-snooze/ack",
		strings.NewReader(`{"snooze_until":"not-a-time"}`))
	req.Header.Set("Content-Type", "application/json")
	req.SetPathValue("fingerprint", "fp-snooze")
	req = req.WithContext(withActor(req.Context(), adminActor()))
	w := httptest.NewRecorder()
	srv.handleAckAlert(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d body=%s", w.Code, w.Body.String())
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
