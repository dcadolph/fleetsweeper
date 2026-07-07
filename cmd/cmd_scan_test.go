package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
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
// and unknown names are silently dropped.
func TestSelectScanners(t *testing.T) {
	t.Parallel()
	reg := buildRegistry()
	all := reg.All()

	// Test 0: Empty names returns the full set.
	if got := selectScanners(reg, nil); len(got) != len(all) {
		t.Errorf("empty selection: got %d, want %d", len(got), len(all))
	}

	// Test 1: A known subset is selected, unknown names ignored.
	got := selectScanners(reg, []string{"version", "not-a-real-scanner"})
	if len(got) != 1 {
		t.Fatalf("subset selection: got %d, want 1", len(got))
	}
	if _, ok := got["version"]; !ok {
		t.Error("expected 'version' in selection")
	}
}

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

// TestRunScannersNoClients verifies the fan-out harness returns an empty
// result set when there are no clients to scan, exercising the span setup and
// wait/return path without touching a cluster.
func TestRunScannersNoClients(t *testing.T) {
	t.Parallel()
	reg := buildRegistry()
	selected := selectScanners(reg, []string{"version"})
	got := runScanners(context.Background(), nil, selected, 2, 0)
	if got == nil {
		t.Fatal("runScanners returned nil map")
	}
	if len(got) != 0 {
		t.Errorf("no clients should yield no results, got %d", len(got))
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
