package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/admission"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// TestResolveScheduleContexts verifies the explicit and all-contexts branches.
func TestResolveScheduleContexts(t *testing.T) {
	t.Parallel()

	// Explicit list passes through when all=false.
	got, err := resolveScheduleContexts("", []string{"a", "b"}, false)
	if err != nil {
		t.Fatalf("explicit: %v", err)
	}
	if diff := cmp.Diff([]string{"a", "b"}, got); diff != "" {
		t.Errorf("explicit mismatch (-want +got):\n%s", diff)
	}

	// all=true reads the kubeconfig contexts.
	kubeconfig := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(kubeconfig, []byte(testKubeconfig), 0o600); err != nil {
		t.Fatalf("write kubeconfig: %v", err)
	}
	names, err := resolveScheduleContexts(kubeconfig, nil, true)
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if diff := cmp.Diff([]string{"alpha", "beta"}, names); diff != "" {
		t.Errorf("all-contexts mismatch (-want +got):\n%s", diff)
	}
}

// TestOpenServeStore verifies the demo in-memory store, the demo's refusal of
// a --db, the missing-db error, and opening a real path.
func TestOpenServeStore(t *testing.T) {
	// Demo mode with no --db falls back to an in-memory store.
	st, err := openServeStore(newStoreCmd(""), true)
	if err != nil {
		t.Fatalf("demo: %v", err)
	}
	if st == nil {
		t.Fatal("demo store is nil")
	}
	st.Close()

	// Demo mode refuses a --db rather than seed the demo into it.
	if _, err := openServeStore(newStoreCmd(filepath.Join(t.TempDir(), "x.db")), true); !errors.Is(err, ErrDemoDatabase) {
		t.Errorf("demo with --db: want ErrDemoDatabase, got %v", err)
	}

	// Non-demo with no --db is an error.
	if _, err := openServeStore(newStoreCmd(""), false); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("no-db non-demo: want ErrNoDatabase, got %v", err)
	}

	// A real path opens successfully.
	dbPath := filepath.Join(t.TempDir(), "serve.db")
	if s, err := store.NewSQLite(dbPath); err != nil {
		t.Fatalf("seed: %v", err)
	} else {
		s.Close()
	}
	real, err := openServeStore(newStoreCmd(dbPath), false)
	if err != nil {
		t.Fatalf("real path: %v", err)
	}
	real.Close()
}

// TestServeFlagsRegistered verifies every flag runServe reads is registered on serveCmd. A flag
// read but never registered silently yields its zero value, and a deployment that passes it
// fails with an unknown-flag error.
func TestServeFlagsRegistered(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("cmd_serve.go")
	if err != nil {
		t.Fatalf("read source: %v", err)
	}
	reads := regexp.MustCompile(`cmd\.Flags\(\)\.Get[A-Za-z0-9]+\("([a-z0-9-]+)"\)`).FindAllSubmatch(src, -1)
	if len(reads) < 30 {
		t.Fatalf("found only %d flag reads; the pattern no longer matches the source", len(reads))
	}
	defer lockRootCmd(t)()
	for _, m := range reads {
		name := string(m[1])
		if serveCmd.Flags().Lookup(name) == nil && serveCmd.InheritedFlags().Lookup(name) == nil &&
			rootCmd.PersistentFlags().Lookup(name) == nil {
			t.Errorf("flag --%s is read by runServe but never registered", name)
		}
	}
}

// errLeaseAPI stands in for a leader election failure in TestCampaign.
var errLeaseAPI = errors.New("lease api unavailable")

// TestCampaign verifies campaign stands for election again after each lost term, stops when its
// context ends, and returns an election error instead of falling back to running unelected.
func TestCampaign(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Want        error
		Outcomes    []error
		CancelAfter int
		PreCanceled bool
		WantTerms   int
	}{{ // Test 0: Two lost terms, then the process shuts down during the third.
		Outcomes: []error{nil, nil, nil}, CancelAfter: 3, WantTerms: 3,
	}, { // Test 1: An election error on the second term is returned and nothing runs after it.
		Outcomes: []error{nil, errLeaseAPI, nil}, CancelAfter: 99, WantTerms: 2, Want: errLeaseAPI,
	}, { // Test 2: An already canceled context runs no term.
		Outcomes: []error{nil}, CancelAfter: 99, PreCanceled: true, WantTerms: 0,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if test.PreCanceled {
				cancel()
			}
			terms := 0
			err := campaign(ctx, zap.NewNop(), func(context.Context) error {
				terms++
				if terms >= test.CancelAfter {
					cancel()
				}
				if terms > len(test.Outcomes) {
					t.Fatalf("term %d ran past the scripted outcomes", terms)
				}
				return test.Outcomes[terms-1]
			})
			if !errors.Is(err, test.Want) {
				t.Errorf("err = %v, want %v", err, test.Want)
			}
			if terms != test.WantTerms {
				t.Errorf("terms = %d, want %d", terms, test.WantTerms)
			}
		})
	}
}

// TestNewAdmissionProvider verifies a pinned baseline file overrides the store, the store
// provider loads one baseline per scan in the stability window, and bad input is rejected.
func TestNewAdmissionProvider(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "adm.db")
	seedBaselineStore(t, dbPath)
	pinned := filepath.Join(dir, "pinned.yaml")
	if err := os.WriteFile(pinned, []byte("sample_pods: 50\nsample_containers: 100\ndigest_pin_fraction: 0.5\n"), 0o600); err != nil {
		t.Fatalf("write pinned: %v", err)
	}
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("digest_pin_fraction: 2\n"), 0o600); err != nil {
		t.Fatalf("write bad: %v", err)
	}
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	tests := []struct {
		Want        error
		PinPath     string
		StableScans int
		WantDigest  float64
		WantPinned  bool
		WantDepth   int
	}{{ // Test 0: A pinned file overrides the store's baseline.
		PinPath: pinned, StableScans: 3, WantDigest: 0.5, WantPinned: true,
	}, { // Test 1: Without a file the store supplies the baseline over the stability window.
		StableScans: 4, WantDigest: 0.9, WantDepth: 4,
	}, { // Test 2: A window below one is rejected.
		StableScans: 0, Want: ErrStableScans,
	}, { // Test 3: An invalid pinned file is rejected.
		PinPath: bad, StableScans: 3, Want: admission.ErrBaselineFile,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			p, err := newAdmissionProvider(test.PinPath, test.StableScans, s, zap.NewNop())
			if !errors.Is(err, test.Want) {
				t.Fatalf("err = %v, want %v", err, test.Want)
			}
			if err != nil {
				return
			}
			b := p.Current(context.Background())
			if b.DigestPinFraction != test.WantDigest || b.Pinned != test.WantPinned {
				t.Errorf("baseline digest = %v pinned = %v, want %v and %v",
					b.DigestPinFraction, b.Pinned, test.WantDigest, test.WantPinned)
			}
			if sp, ok := p.(*admission.StoreBaselineProvider); ok && sp.Depth != test.WantDepth {
				t.Errorf("Depth = %d, want %d", sp.Depth, test.WantDepth)
			}
		})
	}
}

// TestLeaderElectionPlan verifies when serve runs leader election and when it warns that it
// does not.
func TestLeaderElectionPlan(t *testing.T) {
	t.Parallel()
	tests := []struct {
		InCluster     bool
		Namespace     string
		WantEnabled   bool
		WantReasonHas string
	}{{ // Test 0: in a cluster with a namespace, election runs.
		InCluster: true, Namespace: "fleetsweeper", WantEnabled: true,
	}, { // Test 1: in a cluster without a namespace, election is off with a reason.
		InCluster: true, WantReasonHas: "POD_NAMESPACE",
	}, { // Test 2: out of a cluster, election is off without a warning.
		Namespace: "fleetsweeper",
	}, { // Test 3: out of a cluster with no namespace, still no warning.
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			enabled, reason := leaderElectionPlan(test.InCluster, test.Namespace)
			if diff := cmp.Diff(test.WantEnabled, enabled); diff != "" {
				t.Errorf("enabled mismatch (-want +got):\n%s", diff)
			}
			if test.WantReasonHas == "" && reason != "" {
				t.Errorf("want no reason, got %q", reason)
			}
			if !strings.Contains(reason, test.WantReasonHas) {
				t.Errorf("reason %q does not name %q", reason, test.WantReasonHas)
			}
		})
	}
}
