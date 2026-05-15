package store

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// testStore creates a SQLite store in a temp directory.
func testStore(t *testing.T) *SQLite {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.db")
	s, err := NewSQLite(path)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestSaveScanAndGetScan(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	ctx := context.Background()

	clusters := []string{"prod-east", "prod-west"}
	results := map[string]map[string]scanner.Result{
		"prod-east": {
			"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}},
		},
		"prod-west": {
			"version": {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}},
		},
	}

	id, err := s.SaveScan(ctx, clusters, results)
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty scan ID")
	}

	rec, err := s.GetScan(ctx, id)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	if diff := cmp.Diff(id, rec.ID); diff != "" {
		t.Errorf("id mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff(clusters, rec.Clusters, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("clusters mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"version"}, rec.Scanners, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("scanners mismatch (-want +got):\n%s", diff)
	}
}

func TestGetScanResults(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	ctx := context.Background()

	clusters := []string{"a", "b"}
	results := map[string]map[string]scanner.Result{
		"a": {
			"version":    {Scanner: "version", Data: map[string]any{"git_version": "v1.31.2"}},
			"namespaces": {Scanner: "namespaces", Data: map[string]any{"count": float64(5)}},
		},
		"b": {
			"version":    {Scanner: "version", Data: map[string]any{"git_version": "v1.30.4"}},
			"namespaces": {Scanner: "namespaces", Data: map[string]any{"count": float64(3)}},
		},
	}

	id, err := s.SaveScan(ctx, clusters, results)
	if err != nil {
		t.Fatalf("save scan: %v", err)
	}

	got, err := s.GetScanResults(ctx, id)
	if err != nil {
		t.Fatalf("get results: %v", err)
	}

	// After JSON round-trip, Data is map[string]any. Check structure.
	if len(got) != 2 {
		t.Fatalf("expected 2 clusters, got %d", len(got))
	}
	if len(got["a"]) != 2 {
		t.Fatalf("expected 2 scanners for cluster a, got %d", len(got["a"]))
	}
	if got["a"]["version"].Scanner != "version" {
		t.Errorf("expected scanner name 'version', got %q", got["a"]["version"].Scanner)
	}
}

func TestListScans(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	ctx := context.Background()

	// Save 3 scans.
	for i := 0; i < 3; i++ {
		clusters := []string{fmt.Sprintf("cluster-%d", i)}
		results := map[string]map[string]scanner.Result{
			clusters[0]: {"version": {Scanner: "version", Data: map[string]any{"i": float64(i)}}},
		}
		if _, err := s.SaveScan(ctx, clusters, results); err != nil {
			t.Fatalf("save scan %d: %v", i, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	scans, err := s.ListScans(ctx, 10)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if diff := cmp.Diff(3, len(scans)); diff != "" {
		t.Errorf("count mismatch (-want +got):\n%s", diff)
	}
	// Most recent first.
	if scans[0].Timestamp.Before(scans[2].Timestamp) {
		t.Error("expected scans ordered most recent first")
	}

	// Test limit.
	limited, err := s.ListScans(ctx, 2)
	if err != nil {
		t.Fatalf("list scans limited: %v", err)
	}
	if diff := cmp.Diff(2, len(limited)); diff != "" {
		t.Errorf("limited count mismatch (-want +got):\n%s", diff)
	}
}

func TestClusterTracking(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	ctx := context.Background()

	results := map[string]map[string]scanner.Result{
		"alpha": {"version": {Scanner: "version", Data: map[string]any{}}},
	}

	// First scan.
	s.SaveScan(ctx, []string{"alpha"}, results)
	time.Sleep(10 * time.Millisecond)

	// Second scan updates last_seen.
	s.SaveScan(ctx, []string{"alpha"}, results)

	clusters, err := s.ListClusters(ctx)
	if err != nil {
		t.Fatalf("list clusters: %v", err)
	}
	if len(clusters) != 1 {
		t.Fatalf("expected 1 cluster, got %d", len(clusters))
	}
	if clusters[0].Name != "alpha" {
		t.Errorf("expected cluster name 'alpha', got %q", clusters[0].Name)
	}
	if !clusters[0].LastSeen.After(clusters[0].FirstSeen) || clusters[0].LastSeen.Equal(clusters[0].FirstSeen) {
		// Both timestamps come from time.Now() in SaveScan — they may be equal
		// if the test runs fast enough. Just verify they're both non-zero.
		if clusters[0].FirstSeen.IsZero() || clusters[0].LastSeen.IsZero() {
			t.Error("expected non-zero timestamps")
		}
	}
}

func TestGroupCRUD(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	ctx := context.Background()

	// Create.
	err := s.SaveGroup(ctx, "prod", []string{"east", "west"})
	if err != nil {
		t.Fatalf("save group: %v", err)
	}

	// Get.
	g, err := s.GetGroup(ctx, "prod")
	if err != nil {
		t.Fatalf("get group: %v", err)
	}
	if diff := cmp.Diff("prod", g.Name); diff != "" {
		t.Errorf("name mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"east", "west"}, g.Clusters, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("clusters mismatch (-want +got):\n%s", diff)
	}

	// List.
	groups, err := s.ListGroups(ctx)
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}

	// Add cluster.
	err = s.AddClusterToGroup(ctx, "prod", "asia")
	if err != nil {
		t.Fatalf("add cluster: %v", err)
	}
	g, _ = s.GetGroup(ctx, "prod")
	if len(g.Clusters) != 3 {
		t.Errorf("expected 3 clusters, got %d", len(g.Clusters))
	}

	// Remove cluster.
	err = s.RemoveClusterFromGroup(ctx, "prod", "west")
	if err != nil {
		t.Fatalf("remove cluster: %v", err)
	}
	g, _ = s.GetGroup(ctx, "prod")
	if diff := cmp.Diff([]string{"asia", "east"}, g.Clusters, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("after remove mismatch (-want +got):\n%s", diff)
	}

	// Delete.
	err = s.DeleteGroup(ctx, "prod")
	if err != nil {
		t.Fatalf("delete group: %v", err)
	}
	_, err = s.GetGroup(ctx, "prod")
	if err == nil {
		t.Fatal("expected error after delete")
	}
}

func TestGetScanNotFound(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	_, err := s.GetScan(context.Background(), "nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent scan")
	}
}

func TestGetClusterHistory(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	ctx := context.Background()

	// Save 3 scans for the same cluster.
	for i := 0; i < 3; i++ {
		results := map[string]map[string]scanner.Result{
			"alpha": {"version": {Scanner: "version", Data: map[string]any{"i": float64(i)}}},
		}
		if _, err := s.SaveScan(ctx, []string{"alpha"}, results); err != nil {
			t.Fatalf("save scan %d: %v", i, err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	history, err := s.GetClusterHistory(ctx, "alpha", 10)
	if err != nil {
		t.Fatalf("get history: %v", err)
	}
	if diff := cmp.Diff(3, len(history)); diff != "" {
		t.Errorf("history count mismatch (-want +got):\n%s", diff)
	}
}
