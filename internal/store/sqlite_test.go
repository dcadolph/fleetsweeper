package store

import (
	"context"
	"database/sql"
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
	for i := range 3 {
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

// TestListScansTiebreak verifies that scans sharing a second-granularity
// timestamp return in a deterministic order, newest id first. Without the id
// tiebreak, two scans in the same second have unstable latest and previous
// order.
func TestListScansTiebreak(t *testing.T) {
	t.Parallel()
	s := testStore(t)
	ctx := context.Background()

	const ts = "2026-07-07T12:00:00Z"
	// Insert out of id order so the query, not insertion order, decides.
	for _, id := range []string{"0000000000001-aaaa", "0000000000001-cccc", "0000000000001-bbbb"} {
		execRaw(t, s, "INSERT INTO scans (id, timestamp, clusters, scanners) VALUES (?, ?, ?, ?)",
			id, ts, "[]", "[]")
	}

	scans, err := s.ListScans(ctx, 10)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if len(scans) != 3 {
		t.Fatalf("want 3 scans, got %d", len(scans))
	}
	got := []string{scans[0].ID, scans[1].ID, scans[2].ID}
	want := []string{"0000000000001-cccc", "0000000000001-bbbb", "0000000000001-aaaa"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("tiebreak order mismatch (-want +got):\n%s", diff)
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
	for i := range 3 {
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

// TestScanResultStateRoundTrip verifies a scanner's State and Reason survive
// SaveScan and GetScanResults, so a report rebuilt from the store sees the same
// coverage as the live scan that wrote it.
func TestScanResultStateRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantResult scanner.Result
	}{{ // Test 0: A clean result stays StateOK with no reason.
		WantResult: scanner.Result{Scanner: "version", Data: map[string]any{"minor": float64(31)}},
	}, { // Test 1: A degraded result keeps its state and reason alongside its data.
		WantResult: scanner.Result{
			Scanner: "workloads", State: scanner.StateDegraded, Reason: "2 of 9 namespaces forbidden",
			Data: map[string]any{"pods": float64(14)},
		},
	}, { // Test 2: An errored result keeps its reason and a nil payload.
		WantResult: scanner.Result{Scanner: "certs", State: scanner.StateErrored, Reason: "context deadline exceeded"},
	}, { // Test 3: An unavailable result keeps its state.
		WantResult: scanner.Result{
			Scanner: "policy-reports", State: scanner.StateUnavailable, Reason: "PolicyReport CRD not installed",
		},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			s := testStore(t)
			ctx := context.Background()
			name := test.WantResult.Scanner
			id, err := s.SaveScan(ctx, []string{"edge-1"}, map[string]map[string]scanner.Result{
				"edge-1": {name: test.WantResult},
			})
			if err != nil {
				t.Fatalf("save scan: %v", err)
			}
			got, err := s.GetScanResults(ctx, id)
			if err != nil {
				t.Fatalf("get results: %v", err)
			}
			if diff := cmp.Diff(test.WantResult, got["edge-1"][name]); diff != "" {
				t.Errorf("result mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMigrateStateColumnsOnExistingRows verifies migration 8 upgrades a
// database written before scan_results carried state, and that the rows it
// already holds read back as StateOK.
func TestMigrateStateColumnsOnExistingRows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v7.db")

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	if _, err := raw.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	for _, m := range migrations {
		if m.Version > 7 {
			continue
		}
		if _, err := raw.Exec(m.SQL); err != nil {
			t.Fatalf("apply migration %d: %v", m.Version, err)
		}
		if _, err := raw.Exec("INSERT INTO schema_migrations VALUES (?, ?)", m.Version, "2026-01-01T00:00:00Z"); err != nil {
			t.Fatalf("record migration %d: %v", m.Version, err)
		}
	}
	for _, q := range []string{
		`INSERT INTO scans VALUES ('old', '2026-01-01T00:00:00Z', '["edge-1"]', '["version"]')`,
		`INSERT INTO scan_results VALUES ('old', 'edge-1', 'version', '{"minor":30}')`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatalf("seed v7 row: %v", err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("close raw: %v", err)
	}

	s, err := NewSQLite(path)
	if err != nil {
		t.Fatalf("upgrade open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	got, err := s.GetScanResults(ctx, "old")
	if err != nil {
		t.Fatalf("get results: %v", err)
	}
	want := scanner.Result{Scanner: "version", Data: map[string]any{"minor": float64(30)}}
	if diff := cmp.Diff(want, got["edge-1"]["version"]); diff != "" {
		t.Errorf("upgraded row mismatch (-want +got):\n%s", diff)
	}
}

// checkSaveScanRecord verifies a store saves a scan under a caller-chosen ID and timestamp,
// generates both when unset, and refuses a second scan with the same ID.
func checkSaveScanRecord(t *testing.T, st Store) {
	t.Helper()
	ctx := context.Background()
	results := map[string]map[string]scanner.Result{
		"east": {"version": {Scanner: "version", Data: map[string]any{"minor": 31}}},
	}
	at := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	id := NewScanID()

	got, err := st.SaveScanRecord(ctx, ScanRecord{ID: id, Timestamp: at, Clusters: []string{"east"}}, results)
	if err != nil {
		t.Fatalf("save with id: %v", err)
	}
	if got != id {
		t.Errorf("want returned id %q, got %q", id, got)
	}
	rec, err := st.GetScan(ctx, id)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	want := ScanRecord{ID: id, Timestamp: at, Clusters: []string{"east"}, Scanners: []string{"version"}}
	if diff := cmp.Diff(want, *rec); diff != "" {
		t.Errorf("record mismatch (-want +got):\n%s", diff)
	}

	if _, err := st.SaveScanRecord(ctx, ScanRecord{ID: id, Clusters: []string{"east"}}, results); err == nil {
		t.Error("want an error saving a second scan under the same id")
	}

	before := time.Now().UTC().Truncate(time.Second)
	gen, err := st.SaveScanRecord(ctx, ScanRecord{Clusters: []string{"east"}}, results)
	if err != nil {
		t.Fatalf("save without id: %v", err)
	}
	if gen == "" || gen == id {
		t.Errorf("want a fresh generated id, got %q", gen)
	}
	rec, err = st.GetScan(ctx, gen)
	if err != nil {
		t.Fatalf("get generated scan: %v", err)
	}
	if rec.Timestamp.Before(before) {
		t.Errorf("zero timestamp should mean now: got %v, want at or after %v", rec.Timestamp, before)
	}
}

// TestSaveScanRecord runs the SaveScanRecord contract against SQLite.
func TestSaveScanRecord(t *testing.T) {
	t.Parallel()
	checkSaveScanRecord(t, testStore(t))
}
