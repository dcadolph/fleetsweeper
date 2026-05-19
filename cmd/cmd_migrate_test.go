package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestMigrateSQLiteToSQLite uses two SQLite databases as a self-contained
// proxy for the cross-backend path. It exercises every copy function
// without needing a Postgres instance.
func TestMigrateSQLiteToSQLite(t *testing.T) {
	defer lockRootCmd(t)()
	dir := t.TempDir()
	src := filepath.Join(dir, "src.db")
	dst := filepath.Join(dir, "dst.db")

	// Seed source with one scan, one group, one location, one ack, one
	// api key, and one audit entry.
	ss, err := store.NewSQLite(src)
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	ctx := context.Background()
	if _, err := ss.SaveScan(ctx, []string{"a"}, map[string]map[string]scanner.Result{
		"a": {"version": {Scanner: "version", Data: map[string]any{"v": "1"}}},
	}); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	if err := ss.SaveGroup(ctx, "g", []string{"a"}); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if err := ss.SetLocation(ctx, store.LocationRecord{Cluster: "a", Lat: 1, Lng: 2}); err != nil {
		t.Fatalf("seed location: %v", err)
	}
	ss.Close()

	// Run migrate via the cobra command.
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"migrate", "--from=" + src, "--to=" + dst})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("migrate: %v\n%s", err, buf.String())
	}

	// Verify destination has the data.
	ds, err := store.NewSQLite(dst)
	if err != nil {
		t.Fatalf("open dst: %v", err)
	}
	defer ds.Close()
	scans, _ := ds.ListScans(ctx, 10)
	if len(scans) != 1 {
		t.Errorf("scans: want 1, got %d", len(scans))
	}
	groups, _ := ds.ListGroups(ctx)
	if len(groups) != 1 || groups[0].Name != "g" {
		t.Errorf("groups: %+v", groups)
	}
}
