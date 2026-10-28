package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestMigrateSQLiteToSQLite uses two SQLite databases as a self-contained proxy for the
// cross-backend path. Scans keep their IDs and timestamps, and groups, locations, tags, and
// alerts all arrive.
func TestMigrateSQLiteToSQLite(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	dst := filepath.Join(dir, "dst.db")
	ctx := context.Background()

	ss, err := store.NewSQLite(src)
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	wantScans := []store.ScanRecord{{
		ID:        "scan-new",
		Timestamp: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
		Clusters:  []string{"a", "b"},
	}, {
		ID:        "scan-old",
		Timestamp: time.Date(2025, 11, 30, 23, 0, 0, 0, time.UTC),
		Clusters:  []string{"a"},
	}}
	for i, rec := range wantScans {
		results := map[string]map[string]scanner.Result{}
		for _, c := range rec.Clusters {
			results[c] = map[string]scanner.Result{"version": {Scanner: "version", Data: map[string]any{"v": i}}}
		}
		if _, err := ss.SaveScanRecord(ctx, rec, results); err != nil {
			t.Fatalf("seed scan %s: %v", rec.ID, err)
		}
	}
	if err := ss.SaveGroup(ctx, "g", []string{"a"}); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if err := ss.SetLocation(ctx, store.LocationRecord{Cluster: "a", Lat: 1, Lng: 2}); err != nil {
		t.Fatalf("seed location: %v", err)
	}
	for _, kv := range [][3]string{{"a", "env", "prod"}, {"a", "tier", "critical"}, {"b", "env", "dev"}} {
		if err := ss.SetClusterTag(ctx, kv[0], kv[1], kv[2]); err != nil {
			t.Fatalf("seed tag: %v", err)
		}
	}
	wantAlert := store.AlertRecord{
		Fingerprint: "fp-1",
		Cluster:     "a",
		Status:      "firing",
		AlertName:   "KubeNodeNotReady",
		Severity:    "critical",
		StartsAt:    time.Date(2026, 2, 3, 4, 0, 0, 0, time.UTC),
		ReceivedAt:  time.Date(2026, 2, 3, 4, 1, 0, 0, time.UTC),
		Labels:      map[string]string{"alertname": "KubeNodeNotReady", "cluster": "a"},
		Annotations: map[string]string{},
	}
	if err := ss.UpsertAlert(ctx, wantAlert); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	srcScans, err := ss.ListScans(ctx, 10)
	if err != nil {
		t.Fatalf("list src scans: %v", err)
	}
	ss.Close()
	opts := cmp.Options{
		cmpopts.IgnoreFields(store.ScanRecord{}, "Scanners"),
		cmpopts.EquateEmpty(),
	}
	if diff := cmp.Diff(wantScans, srcScans, opts...); diff != "" {
		t.Fatalf("seeded scans mismatch (-want +got):\n%s", diff)
	}

	func() {
		defer lockRootCmd(t)()
		buf := &bytes.Buffer{}
		rootCmd.SetOut(buf)
		rootCmd.SetErr(buf)
		rootCmd.SetArgs([]string{"migrate", "--from=" + src, "--to=" + dst, "--force=false", "--verify=true"})
		if err := rootCmd.Execute(); err != nil {
			t.Fatalf("migrate: %v\n%s", err, buf.String())
		}
	}()

	ds, err := store.NewSQLite(dst)
	if err != nil {
		t.Fatalf("open dst: %v", err)
	}
	defer ds.Close()

	scans, err := ds.ListScans(ctx, 10)
	if err != nil {
		t.Fatalf("list scans: %v", err)
	}
	if diff := cmp.Diff(srcScans, scans, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("scans mismatch (-want +got):\n%s", diff)
	}
	results, err := ds.GetScanResults(ctx, "scan-new")
	if err != nil {
		t.Fatalf("get results: %v", err)
	}
	if len(results) != 2 {
		t.Errorf("scan-new results: want 2 clusters, got %d", len(results))
	}

	groups, err := ds.ListGroups(ctx)
	if err != nil {
		t.Fatalf("list groups: %v", err)
	}
	if len(groups) != 1 || groups[0].Name != "g" {
		t.Errorf("groups: %+v", groups)
	}

	tags, err := ds.ListClusterTags(ctx)
	if err != nil {
		t.Fatalf("list tags: %v", err)
	}
	wantTags := map[string]map[string]string{"a": {"env": "prod", "tier": "critical"}, "b": {"env": "dev"}}
	if diff := cmp.Diff(wantTags, tags); diff != "" {
		t.Errorf("tags mismatch (-want +got):\n%s", diff)
	}

	alerts, err := ds.ListAlerts(ctx, store.AlertListOptions{})
	if err != nil {
		t.Fatalf("list alerts: %v", err)
	}
	if diff := cmp.Diff([]store.AlertRecord{wantAlert}, alerts, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("alerts mismatch (-want +got):\n%s", diff)
	}
}

// TestMigrateSkipsExistingAPIKey verifies a forced migrate into a destination that already holds
// the source's api key skips that key and succeeds.
func TestMigrateSkipsExistingAPIKey(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	dst := filepath.Join(dir, "dst.db")
	ctx := context.Background()
	key := store.APIKeyRecord{
		ID: "key-1", TokenHash: "hash-1", Name: "ci", Role: store.RoleAdmin,
		CreatedAt: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
	}
	for _, path := range []string{src, dst} {
		s, err := store.NewSQLite(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		if err := s.SaveAPIKey(ctx, key); err != nil {
			t.Fatalf("seed key in %s: %v", path, err)
		}
		s.Close()
	}

	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"migrate", "--from=" + src, "--to=" + dst, "--force=true", "--verify=true"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("migrate: %v\n%s", err, buf.String())
	}
	if !strings.Contains(buf.String(), "api keys:  0 copied, 1 already present") {
		t.Errorf("output does not report the skipped key:\n%s", buf.String())
	}
	ds, err := store.NewSQLite(dst)
	if err != nil {
		t.Fatalf("open dst: %v", err)
	}
	defer ds.Close()
	keys, err := ds.ListAPIKeys(ctx)
	if err != nil {
		t.Fatalf("list keys: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("dst keys: want 1, got %d", len(keys))
	}
}
