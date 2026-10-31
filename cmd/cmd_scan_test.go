package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/cohort"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/server"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestBuildRegistry verifies every expected scanner registers exactly once.
func TestBuildRegistry(t *testing.T) {
	t.Parallel()
	reg := buildRegistry()
	all := reg.All()
	// The architecture registers 24 scanners. A drift here means a scanner
	// was added or dropped without updating this guard.
	if len(all) != 24 {
		t.Errorf("registered scanner count: got %d, want 24", len(all))
	}
	// Spot-check a handful resolve by name through Get.
	for _, name := range []string{"version", "image-audit", "workload-security"} {
		if _, ok := reg.Get(name); !ok {
			t.Errorf("expected scanner %q to be registered", name)
		}
	}
}

// TestSelectScanners verifies empty selection means all, a subset is honored,
// TestResolveContexts verifies the explicit, none, and all-contexts branches.
func TestResolveContexts(t *testing.T) {
	t.Parallel()

	// Test 0: Explicit contexts pass through unchanged.
	got, err := resolveContexts("", []string{"a", "b"}, false)
	if err != nil {
		t.Fatalf("explicit: %v", err)
	}
	if diff := cmp.Diff([]string{"a", "b"}, got); diff != "" {
		t.Errorf("explicit mismatch (-want +got):\n%s", diff)
	}

	// Test 1: No contexts and all=false is an error.
	if _, err := resolveContexts("", nil, false); !errors.Is(err, ErrNoContexts) {
		t.Errorf("want ErrNoContexts, got %v", err)
	}

	// Test 2: all=true reads context names from the kubeconfig.
	kubeconfig := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(kubeconfig, []byte(testKubeconfig), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	names, err := resolveContexts(kubeconfig, nil, true)
	if err != nil {
		t.Fatalf("all-contexts: %v", err)
	}
	if diff := cmp.Diff([]string{"alpha", "beta"}, names); diff != "" {
		t.Errorf("all-contexts mismatch (-want +got):\n%s", diff)
	}
}

// testKubeconfig is a minimal two-context kubeconfig fixture.
const testKubeconfig = `apiVersion: v1
kind: Config
clusters:
- name: c1
  cluster:
    server: https://localhost:6443
contexts:
- name: alpha
  context:
    cluster: c1
    user: u1
- name: beta
  context:
    cluster: c1
    user: u1
users:
- name: u1
  user: {}
current-context: alpha
`

// TestScannerCatalogCoversRegistry verifies every registered scanner has a
// label, a description, and a category, and that the catalog lists nothing
// the registry does not run.
func TestScannerCatalogCoversRegistry(t *testing.T) {
	t.Parallel()
	registered := map[string]bool{}
	for _, name := range buildRegistry().Names() {
		registered[name] = true
	}
	catalog := map[string]bool{}
	for _, s := range report.ScannerCatalog() {
		catalog[s.ID] = true
		if !registered[s.ID] {
			t.Errorf("catalog lists %q, which the registry does not run", s.ID)
		}
		if s.Label == "" || s.Description == "" || s.Category == "" {
			t.Errorf("%s: label %q, description %q, category %q", s.ID, s.Label, s.Description, s.Category)
		}
	}
	for name := range registered {
		if !catalog[name] {
			t.Errorf("registered scanner %q is missing from the catalog", name)
		}
	}
	if len(registered) != 24 {
		t.Errorf("registry runs %d scanners, docs and the UI say 24", len(registered))
	}
}

// TestBuildScanReportCohorts verifies the scan command's report reads cohort tags and groups from
// the store, so it partitions a stored scan into the same cohorts the server does.
func TestBuildScanReportCohorts(t *testing.T) {
	t.Parallel()
	edge := []string{"c00", "c01", "c02", "c03", "c04"}
	tests := []struct {
		WantTagged []string
		Want       bool
		Close      bool
		NoStore    bool
	}{{ // Test 0: Stored tags give an edge cohort that matches the server's.
		WantTagged: edge,
	}, { // Test 1: Without a store the report has no tagged cohort.
		NoStore: true,
	}, { // Test 2: A store that cannot list tags fails the report.
		Close: true, Want: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			dbPath := filepath.Join(t.TempDir(), "cohorts.db")
			seedStepScans(t, dbPath)
			st, err := store.NewSQLite(dbPath)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			defer st.Close()
			for _, c := range edge {
				if err := st.SetClusterTag(ctx, c, cohort.DefaultTagKey, "edge"); err != nil {
					t.Fatalf("set tag: %v", err)
				}
			}
			if err := st.SaveGroup(ctx, "prod", []string{"c05", "c06"}); err != nil {
				t.Fatalf("save group: %v", err)
			}
			scan, err := st.GetScan(ctx, "scan-6")
			if err != nil {
				t.Fatalf("get scan: %v", err)
			}
			results, err := st.GetScanResults(ctx, scan.ID)
			if err != nil {
				t.Fatalf("get results: %v", err)
			}
			serverOpts, err := server.StoreReportOptions(ctx, st)
			if err != nil {
				t.Fatalf("server options: %v", err)
			}
			serverOpts.Timestamp = scan.Timestamp
			serverRpt := report.Build(scan.Clusters, results, serverOpts)

			var cliStore store.Store = st
			if test.NoStore {
				cliStore = nil
			}
			if test.Close {
				st.Close()
			}
			rpt, err := buildScanReport(ctx, cliStore, scan.Clusters, results, report.BuildOptions{Timestamp: scan.Timestamp})
			if (err != nil) != test.Want {
				t.Fatalf("err = %v, want error %v", err, test.Want)
			}
			if err != nil {
				return
			}
			var tagged []string
			for _, c := range rpt.Cohorts {
				if c.Source == string(cohort.SourceTagged) && c.Name == "edge" {
					tagged = c.Clusters
				}
			}
			if diff := cmp.Diff(test.WantTagged, tagged, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("edge cohort mismatch (-want +got):\n%s", diff)
			}
			if test.NoStore {
				return
			}
			if diff := cmp.Diff(serverRpt.Cohorts, rpt.Cohorts, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("CLI and server cohorts disagree (-server +cli):\n%s", diff)
			}
		})
	}
}

// TestScanFlagsDefined verifies scan, serve, and watch each define --probe-registries.
func TestScanFlagsDefined(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Cmd      *cobra.Command
		WantFlag string
	}{{ // Test 0: Scan defines the flag.
		Cmd: scanCmd, WantFlag: "probe-registries",
	}, { // Test 1: Serve defines the flag.
		Cmd: serveCmd, WantFlag: "probe-registries",
	}, { // Test 2: Watch defines the flag.
		Cmd: watchCmd, WantFlag: "probe-registries",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			defer lockRootCmd(t)()
			f := test.Cmd.Flags().Lookup(test.WantFlag)
			if f == nil {
				t.Fatalf("%s: flag --%s not defined", test.Cmd.Name(), test.WantFlag)
			}
			if diff := cmp.Diff("false", f.DefValue); diff != "" {
				t.Errorf("default mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
