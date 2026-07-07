package server

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
