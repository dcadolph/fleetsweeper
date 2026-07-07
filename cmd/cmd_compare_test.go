package cmd

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestResolveScanID verifies alias resolution and the pass-through case.
func TestResolveScanID(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "cmp.db")
	ids := seedHistoryScans(t, dbPath, 2)
	idSet := map[string]bool{ids[0]: true, ids[1]: true}

	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	// latest and previous both resolve into the seeded set and differ from
	// each other. Second-granularity timestamps make the absolute order
	// nondeterministic, so membership + distinctness is the stable assertion.
	latest, err := resolveScanID(ctx, s, "latest", 0)
	if err != nil || !idSet[latest] {
		t.Fatalf("latest: id=%q err=%v", latest, err)
	}
	prev, err := resolveScanID(ctx, s, "previous", 0)
	if err != nil || !idSet[prev] {
		t.Fatalf("previous: id=%q err=%v", prev, err)
	}
	if latest == prev {
		t.Errorf("latest and previous resolved to the same id %q", latest)
	}

	// A literal ID passes through unchanged.
	if got, _ := resolveScanID(ctx, s, "verbatim-id", 0); got != "verbatim-id" {
		t.Errorf("verbatim: got %q", got)
	}
}

// TestResolveScanIDErrors verifies the empty-store and single-scan errors.
func TestResolveScanIDErrors(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "cmp.db")
	seedHistoryScans(t, dbPath, 1)
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()
	ctx := context.Background()

	// "previous" needs two scans.
	if _, err := resolveScanID(ctx, s, "previous", 0); err == nil {
		t.Error("expected error resolving previous with one scan")
	}

	// "latest" against a fresh, empty store is an error.
	emptyPath := filepath.Join(t.TempDir(), "empty.db")
	es, _ := store.NewSQLite(emptyPath)
	defer es.Close()
	if _, err := resolveScanID(ctx, es, "latest", 0); err == nil {
		t.Error("expected error resolving latest with no scans")
	}
}

// TestLoadReport verifies a stored scan rebuilds into a report.
func TestLoadReport(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "cmp.db")
	ids := seedHistoryScans(t, dbPath, 1)
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	rpt, err := loadReport(context.Background(), s, ids[0])
	if err != nil {
		t.Fatalf("loadReport: %v", err)
	}
	if len(rpt.Clusters) != 1 || rpt.Clusters[0] != "prod" {
		t.Errorf("report clusters: %v", rpt.Clusters)
	}
}

// execCompare executes the compare subcommand and captures its output, which
// compare writes through cmd.OutOrStdout().
func execCompare(t *testing.T, dbPath string, args ...string) (string, error) {
	t.Helper()
	defer lockRootCmd(t)()
	buf := &bytes.Buffer{}
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	full := append([]string{"compare"}, args...)
	full = append(full, "--db="+dbPath)
	rootCmd.SetArgs(full)
	err := rootCmd.Execute()
	return buf.String(), err
}

// TestCompareFormats verifies text, json, and markdown rendering all run.
func TestCompareFormats(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "cmp.db")
	ids := seedHistoryScans(t, dbPath, 2)

	for _, format := range []string{"text", "json", "markdown"} {
		out, err := execCompare(t, dbPath, ids[0], ids[1], "--format="+format, "--no-color=true")
		if err != nil {
			t.Fatalf("compare %s: %v\n%s", format, err, out)
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("compare %s produced no output", format)
		}
	}
}

// TestCompareRequiresDB verifies the missing-db path surfaces an error.
func TestCompareRequiresDB(t *testing.T) {
	if _, err := execCompare(t, "", "a", "b", "--format=text"); err == nil {
		t.Error("expected error without --db")
	}
}
