package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// seedClusterTimelineData writes one scan covering cluster "prod" plus
// one alert and one ack against the same cluster so the timeline
// handler has something interleaved to return.
func seedClusterTimelineData(t *testing.T, ss *store.SQLite) {
	t.Helper()
	ctx := context.Background()
	results := map[string]map[string]scanner.Result{
		"prod": {"version": {Scanner: "version", Data: map[string]any{"v": "1.30"}}},
	}
	if _, err := ss.SaveScan(ctx, []string{"prod"}, results); err != nil {
		t.Fatalf("save scan: %v", err)
	}
	if err := ss.UpsertAlert(ctx, store.AlertRecord{
		Fingerprint: "fp-1",
		Cluster:     "prod",
		Status:      "firing",
		AlertName:   "HighMemory",
		Severity:    "critical",
		Summary:     "memory above 90%",
		ReceivedAt:  time.Now(),
		Labels:      map[string]string{"cluster": "prod"},
		Annotations: map[string]string{},
	}); err != nil {
		t.Fatalf("save alert: %v", err)
	}
	if err := ss.SaveAck(ctx, store.AckRecord{
		Fingerprint: "ack-fp",
		Cluster:     "prod",
		Title:       "Acked finding",
		AckBy:       "test",
		Reason:      "investigated",
		CreatedAt:   time.Now(),
	}); err != nil {
		t.Fatalf("save ack: %v", err)
	}
}

// TestClusterTimeline_InterleavesAllKinds verifies a scan, an alert,
// and an ack for the same cluster all appear in the timeline response.
func TestClusterTimeline_InterleavesAllKinds(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	seedClusterTimelineData(t, ss)

	req := httptest.NewRequest(http.MethodGet, "/api/clusters/prod/timeline", nil)
	req.SetPathValue("name", "prod")
	w := httptest.NewRecorder()
	srv.handleClusterTimeline(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Cluster string          `json:"cluster"`
		Count   int             `json:"count"`
		Entries []timelineEntry `json:"entries"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Cluster != "prod" {
		t.Errorf("cluster: %q", resp.Cluster)
	}
	kinds := map[string]int{}
	for _, e := range resp.Entries {
		kinds[e.Kind]++
	}
	if kinds["scan"] == 0 || kinds["alert"] == 0 || kinds["ack"] == 0 {
		t.Errorf("missing some kinds, got %+v", kinds)
	}
}

// TestClusterTimeline_FiltersToCluster verifies scans for other
// clusters and alerts on other clusters are excluded.
func TestClusterTimeline_FiltersToCluster(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	if _, err := ss.SaveScan(ctx, []string{"other"}, map[string]map[string]scanner.Result{
		"other": {"version": {Scanner: "version", Data: map[string]any{"v": "1.30"}}},
	}); err != nil {
		t.Fatalf("save: %v", err)
	}
	if err := ss.UpsertAlert(ctx, store.AlertRecord{
		Fingerprint: "fp-other", Cluster: "other", Status: "firing",
		AlertName: "X", ReceivedAt: time.Now(),
		Labels: map[string]string{}, Annotations: map[string]string{},
	}); err != nil {
		t.Fatalf("alert: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/clusters/prod/timeline", nil)
	req.SetPathValue("name", "prod")
	w := httptest.NewRecorder()
	srv.handleClusterTimeline(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	var resp struct {
		Count   int             `json:"count"`
		Entries []timelineEntry `json:"entries"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Count != 0 {
		t.Errorf("expected 0 entries for cluster prod, got %d: %+v", resp.Count, resp.Entries)
	}
}

// TestClusterTimeline_NewestFirst verifies entries are sorted
// reverse-chronologically.
func TestClusterTimeline_NewestFirst(t *testing.T) {
	t.Parallel()
	srv, ss := testServer(t)
	ctx := context.Background()
	older := time.Now().Add(-2 * time.Hour)
	newer := time.Now().Add(-1 * time.Minute)
	if err := ss.UpsertAlert(ctx, store.AlertRecord{
		Fingerprint: "fp-old", Cluster: "p", Status: "firing",
		AlertName: "Old", ReceivedAt: older,
		Labels: map[string]string{}, Annotations: map[string]string{},
	}); err != nil {
		t.Fatalf("alert: %v", err)
	}
	if err := ss.UpsertAlert(ctx, store.AlertRecord{
		Fingerprint: "fp-new", Cluster: "p", Status: "firing",
		AlertName: "New", ReceivedAt: newer,
		Labels: map[string]string{}, Annotations: map[string]string{},
	}); err != nil {
		t.Fatalf("alert: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/clusters/p/timeline", nil)
	req.SetPathValue("name", "p")
	w := httptest.NewRecorder()
	srv.handleClusterTimeline(w, req)

	var resp struct {
		Entries []timelineEntry `json:"entries"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if len(resp.Entries) != 2 {
		t.Fatalf("want 2 entries, got %d", len(resp.Entries))
	}
	if resp.Entries[0].Title != "New" {
		t.Errorf("newest first: want New, got %q", resp.Entries[0].Title)
	}
}

// TestClusterTimeline_RejectsEmptyCluster verifies the handler 400s
// when the path value is missing.
func TestClusterTimeline_RejectsEmptyCluster(t *testing.T) {
	t.Parallel()
	srv, _ := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/clusters//timeline", nil)
	w := httptest.NewRecorder()
	srv.handleClusterTimeline(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400, got %d", w.Code)
	}
}
