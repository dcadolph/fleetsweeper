package cmd

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestStoreCommandsHonorPostgresDSN verifies offline store commands open a Postgres DSN with the
// Postgres driver rather than handing it to SQLite as a file path.
func TestStoreCommandsHonorPostgresDSN(t *testing.T) {
	t.Parallel()
	const dsn = "postgres://u:p@127.0.0.1:1/x"
	tests := []struct {
		Name string
		Run  func(cmd *cobra.Command, args []string) error
	}{{ // Test 0: group list.
		Name: "group list", Run: runGroupList,
	}, { // Test 1: history list.
		Name: "history list", Run: runHistoryList,
	}, { // Test 2: apikey list.
		Name: "apikey list", Run: runAPIKeyList,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			cmd := newStoreCmd(dsn)
			cmd.Flags().Int("limit", 10, "")
			err := test.Run(cmd, nil)
			if err == nil {
				t.Fatalf("%s: want a connection error, got nil", test.Name)
			}
			if strings.Contains(strings.ToLower(err.Error()), "sqlite") {
				t.Errorf("%s: DSN opened as SQLite: %v", test.Name, err)
			}
		})
	}
}

// newRefStore opens a SQLite store in a temp dir holding n scans of three clusters, an hour
// apart, and tags two of the clusters cohort=a. It returns the store and the scan IDs, oldest
// first.
func newRefStore(t *testing.T, n int) (store.Store, []string) {
	t.Helper()
	st, err := store.NewSQLite(filepath.Join(t.TempDir(), "refs.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx := context.Background()
	clusters := []string{"c1", "c2", "c3"}
	for _, c := range clusters[:2] {
		if err := st.SetClusterTag(ctx, c, "cohort", "a"); err != nil {
			t.Fatalf("tag %s: %v", c, err)
		}
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	ids := make([]string, 0, n)
	for i := range n {
		results := make(map[string]map[string]scanner.Result, len(clusters))
		for j, c := range clusters {
			results[c] = map[string]scanner.Result{"version": {
				Scanner: "version",
				Data:    map[string]any{"server": fmt.Sprintf("v1.%d", 30+j), "nodes": 3 + j},
			}}
		}
		rec := store.ScanRecord{Timestamp: start.Add(time.Duration(i) * time.Hour), Clusters: clusters}
		id, err := st.SaveScanRecord(ctx, rec, results)
		if err != nil {
			t.Fatalf("save scan %d: %v", i, err)
		}
		ids = append(ids, id)
	}
	return st, ids
}

// TestResolveScanRef verifies scan aliases resolve against the store, other refs pass through,
// and an empty store, a short store, and a failing store each return their own error.
func TestResolveScanRef(t *testing.T) {
	t.Parallel()
	two, ids := newRefStore(t, 2)
	one, _ := newRefStore(t, 1)
	empty, _ := newRefStore(t, 0)
	closed, _ := newRefStore(t, 1)
	if err := closed.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	stores := map[string]store.Store{"two": two, "one": one, "empty": empty, "closed": closed}
	tests := []struct {
		Store     string
		Ref       string
		WantID    string
		Want      error
		WantOther bool
	}{{ // Test 0: latest is the newest scan.
		Store: "two", Ref: "latest", WantID: ids[1],
	}, { // Test 1: previous is the scan before it.
		Store: "two", Ref: "previous", WantID: ids[0],
	}, { // Test 2: second-latest is the same scan as previous.
		Store: "two", Ref: "second-latest", WantID: ids[0],
	}, { // Test 3: any other ref is a scan ID and passes through.
		Store: "two", Ref: "scan-x", WantID: "scan-x",
	}, { // Test 4: latest on an empty store.
		Store: "empty", Ref: "latest", Want: ErrNoScans,
	}, { // Test 5: previous on an empty store.
		Store: "empty", Ref: "previous", Want: ErrNoScans,
	}, { // Test 6: previous with one scan.
		Store: "one", Ref: "previous", Want: ErrTooFewScans,
	}, { // Test 7: a failing store returns its own error, not an empty-store error.
		Store: "closed", Ref: "latest", WantOther: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := resolveScanRef(context.Background(), stores[test.Store], test.Ref)
			if test.WantOther {
				if err == nil || errors.Is(err, ErrNoScans) || errors.Is(err, ErrTooFewScans) {
					t.Fatalf("want the store's own error, got %v", err)
				}
				return
			}
			if !errors.Is(err, test.Want) {
				t.Fatalf("error: want %v, got %v", test.Want, err)
			}
			if diff := cmp.Diff(test.WantID, got); diff != "" {
				t.Errorf("id mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestLoadStoredReport verifies a stored scan rebuilds with the store's cohort tags, matching
// the report scan builds for the same results, and that an unknown scan ID errors.
func TestLoadStoredReport(t *testing.T) {
	t.Parallel()
	st, ids := newRefStore(t, 2)
	ctx := context.Background()
	tests := []struct {
		ID          string
		WantCohorts []report.CohortSummary
		WantErr     bool
	}{{ // Test 0: the older scan carries the tagged cohort.
		ID: ids[0], WantCohorts: wantStoredCohorts(t, st, ids[0]),
	}, { // Test 1: the newer scan carries the tagged cohort.
		ID: ids[1], WantCohorts: wantStoredCohorts(t, st, ids[1]),
	}, { // Test 2: an unknown scan ID errors.
		ID: "nope", WantErr: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			rpt, rec, err := loadStoredReport(ctx, st, test.ID)
			if test.WantErr {
				if err == nil {
					t.Fatal("want an error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("load: %v", err)
			}
			if diff := cmp.Diff(test.ID, rec.ID); diff != "" {
				t.Errorf("record mismatch (-want +got):\n%s", diff)
			}
			if !slices.ContainsFunc(rpt.Cohorts, func(c report.CohortSummary) bool {
				return c.Name == "a" && slices.Equal(c.Clusters, []string{"c1", "c2"})
			}) {
				t.Errorf("no tagged cohort a of c1 and c2 in %+v", rpt.Cohorts)
			}
			if diff := cmp.Diff(test.WantCohorts, rpt.Cohorts, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("cohorts mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// wantStoredCohorts returns the cohorts scan builds for a stored scan's results with st's tags.
func wantStoredCohorts(t *testing.T, st store.Store, id string) []report.CohortSummary {
	t.Helper()
	ctx := context.Background()
	rec, err := st.GetScan(ctx, id)
	if err != nil {
		t.Fatalf("get scan: %v", err)
	}
	results, err := st.GetScanResults(ctx, id)
	if err != nil {
		t.Fatalf("get results: %v", err)
	}
	opts := report.BuildOptions{Timestamp: rec.Timestamp}
	rpt, err := buildScanReport(ctx, st, rec.Clusters, results, opts)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	return rpt.Cohorts
}
