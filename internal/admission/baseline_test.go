package admission

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// fakeStore is a partial store.Store used to drive the baseline provider. It
// embeds the interface so unimplemented methods panic if the provider ever
// reaches for them; only ListScans and GetScanResults are wired up.
type fakeStore struct {
	store.Store
	// scans is returned by ListScans.
	scans []store.ScanRecord
	// scansErr is returned alongside scans.
	scansErr error
	// results is returned by GetScanResults.
	results map[string]map[string]scanner.Result
	// resultsErr is returned alongside results.
	resultsErr error
	// listCalls counts ListScans invocations so cache behavior is observable.
	listCalls int
}

// ListScans returns the canned scan records and increments the call counter.
func (f *fakeStore) ListScans(_ context.Context, _ int) ([]store.ScanRecord, error) {
	f.listCalls++
	return f.scans, f.scansErr
}

// GetScanResults returns the canned per-cluster scanner results.
func (f *fakeStore) GetScanResults(_ context.Context, _ string) (map[string]map[string]scanner.Result, error) {
	return f.results, f.resultsErr
}

// imageAuditData builds an image-audit scanner Data payload.
func imageAuditData(totalContainers, noDigest int) scanner.Result {
	return scanner.Result{Scanner: "image-audit", Data: map[string]any{
		"total_containers": totalContainers,
		"no_digest":        noDigest,
	}}
}

// workloadSecData builds a workload-security scanner Data payload.
func workloadSecData(totalPods, runAsRoot, allowPrivEsc, noReadOnly, defaultSA int) scanner.Result {
	return scanner.Result{Scanner: "workload-security", Data: map[string]any{
		"total_pods":                   totalPods,
		"run_as_root_containers":       runAsRoot,
		"allow_privilege_escalation":   allowPrivEsc,
		"no_read_only_root":            noReadOnly,
		"default_service_account_pods": defaultSA,
	}}
}

// TestFloatRatio verifies the ratio helper clamps to [0, 1] and guards a
// zero denominator.
func TestFloatRatio(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantResult float64
		N          int
		D          int
	}{
		{N: 3, D: 4, WantResult: 0.75}, // Test 0: Ordinary fraction.
		{N: 1, D: 0, WantResult: 0},    // Test 1: Zero denominator guards to 0.
		{N: 1, D: -4, WantResult: 0},   // Test 2: Negative denominator guards to 0.
		{N: -5, D: 10, WantResult: 0},  // Test 3: Negative result clamps to 0.
		{N: 15, D: 10, WantResult: 1},  // Test 4: Over-unity result clamps to 1.
		{N: 40, D: 40, WantResult: 1},  // Test 5: Exact unity.
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			got := floatRatio(test.N, test.D)
			if diff := cmp.Diff(test.WantResult, got, cmpopts.EquateApprox(0, 1e-9)); diff != "" {
				t.Errorf("test %d mismatch (-want +got):\n%s", testNum, diff)
			}
		})
	}
}

// TestTallyImageAudit verifies the image-audit payload is decoded into a
// container total and digest-pinned count.
func TestTallyImageAudit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Data      any
		WantTotal int
		WantPin   int
	}{
		{ // Test 0: Ordinary payload.
			Data: map[string]any{"total_containers": 40, "no_digest": 4}, WantTotal: 40, WantPin: 36,
		},
		{ // Test 1: Zero containers yields zeros.
			Data: map[string]any{"total_containers": 0, "no_digest": 0}, WantTotal: 0, WantPin: 0,
		},
		{ // Test 2: Negative container count guards to zeros.
			Data: map[string]any{"total_containers": -5, "no_digest": 0}, WantTotal: 0, WantPin: 0,
		},
		{ // Test 3: Unmarshalable channel value yields zeros.
			Data: make(chan int), WantTotal: 0, WantPin: 0,
		},
		{ // Test 4: JSON shape mismatch (array not object) yields zeros.
			Data: []int{1, 2, 3}, WantTotal: 0, WantPin: 0,
		},
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			total, pin := tallyImageAudit(test.Data)
			if total != test.WantTotal || pin != test.WantPin {
				t.Errorf("test %d: got (%d, %d), want (%d, %d)", testNum, total, pin, test.WantTotal, test.WantPin)
			}
		})
	}
}

// TestTallyWorkloadSec verifies the workload-security payload maps onto the
// internal tally struct and that malformed payloads yield a zero tally.
func TestTallyWorkloadSec(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Data       any
		WantResult workloadSecTally
	}{
		{ // Test 0: Ordinary payload.
			Data: map[string]any{
				"total_pods":                   20,
				"run_as_root_containers":       8,
				"allow_privilege_escalation":   10,
				"no_read_only_root":            12,
				"default_service_account_pods": 5,
			},
			WantResult: workloadSecTally{
				totalPods: 20, runAsRoot: 8, allowPrivEsc: 10, noReadOnlyRoot: 12, defaultSA: 5,
			},
		},
		{ // Test 1: Unmarshalable channel value yields a zero tally.
			Data: make(chan int), WantResult: workloadSecTally{},
		},
		{ // Test 2: JSON shape mismatch yields a zero tally.
			Data: []int{1, 2, 3}, WantResult: workloadSecTally{},
		},
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			got := tallyWorkloadSec(test.Data)
			if diff := cmp.Diff(test.WantResult, got, cmp.AllowUnexported(workloadSecTally{})); diff != "" {
				t.Errorf("test %d mismatch (-want +got):\n%s", testNum, diff)
			}
		})
	}
}

// TestNewStoreBaselineProvider verifies the constructor defaults a
// non-positive TTL to sixty seconds and otherwise honors the caller's value.
func TestNewStoreBaselineProvider(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantTTL time.Duration
		In      time.Duration
	}{
		{In: 0, WantTTL: 60 * time.Second},                // Test 0: Zero defaults.
		{In: -5 * time.Second, WantTTL: 60 * time.Second}, // Test 1: Negative defaults.
		{In: 15 * time.Second, WantTTL: 15 * time.Second}, // Test 2: Positive honored.
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			p := NewStoreBaselineProvider(&fakeStore{}, test.In)
			if p.ttl != test.WantTTL {
				t.Errorf("test %d: ttl = %v, want %v", testNum, p.ttl, test.WantTTL)
			}
		})
	}
}

// TestStoreBaselineProviderRecompute verifies the recompute path tallies the
// scanner payloads into fleet fractions and short-circuits on store errors or
// empty data.
func TestStoreBaselineProviderRecompute(t *testing.T) {
	t.Parallel()
	errBoom := errors.New("boom")
	oneScan := []store.ScanRecord{{ID: "scan-1"}}

	tests := []struct {
		WantBaseline Baseline
		Store        *fakeStore
	}{
		{ // Test 0: Both scanners present produce every fraction.
			Store: &fakeStore{
				scans: oneScan,
				results: map[string]map[string]scanner.Result{
					"clusterA": {
						"image-audit":       imageAuditData(40, 4),
						"workload-security": workloadSecData(20, 8, 10, 12, 5),
					},
				},
			},
			WantBaseline: Baseline{
				SampleContainers:              40,
				SamplePods:                    20,
				DigestPinFraction:             0.9,
				NonRootFraction:               0.8,
				NoPrivilegeEscalationFraction: 0.75,
				ReadOnlyRootFSFraction:        0.7,
				NamedServiceAccountFraction:   0.75,
				SourceScanID:                  "scan-1",
			},
		},
		{ // Test 1: Only image-audit present leaves pod-derived fractions at zero.
			Store: &fakeStore{
				scans: oneScan,
				results: map[string]map[string]scanner.Result{
					"clusterA": {"image-audit": imageAuditData(40, 4)},
				},
			},
			WantBaseline: Baseline{
				SampleContainers:  40,
				DigestPinFraction: 0.9,
				SourceScanID:      "scan-1",
			},
		},
		{ // Test 2: Empty results still records the source scan ID.
			Store:        &fakeStore{scans: oneScan, results: map[string]map[string]scanner.Result{}},
			WantBaseline: Baseline{SourceScanID: "scan-1"},
		},
		{ // Test 3: ListScans error yields the zero baseline.
			Store:        &fakeStore{scansErr: errBoom},
			WantBaseline: Baseline{},
		},
		{ // Test 4: No scans yields the zero baseline.
			Store:        &fakeStore{scans: nil},
			WantBaseline: Baseline{},
		},
		{ // Test 5: GetScanResults error yields the zero baseline.
			Store:        &fakeStore{scans: oneScan, resultsErr: errBoom},
			WantBaseline: Baseline{},
		},
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			p := NewStoreBaselineProvider(test.Store, time.Minute)
			got := p.recompute(context.Background())
			opts := cmp.Options{cmpopts.EquateEmpty(), cmpopts.EquateApprox(0, 1e-9)}
			if diff := cmp.Diff(test.WantBaseline, got, opts); diff != "" {
				t.Errorf("test %d mismatch (-want +got):\n%s", testNum, diff)
			}
		})
	}
}

// TestStoreBaselineProviderCurrentCaches verifies Current recomputes on a cold
// cache, serves the cached value within the TTL, and recomputes again once the
// cache goes stale.
func TestStoreBaselineProviderCurrentCaches(t *testing.T) {
	t.Parallel()
	fs := &fakeStore{
		scans: []store.ScanRecord{{ID: "scan-1"}},
		results: map[string]map[string]scanner.Result{
			"clusterA": {"image-audit": imageAuditData(40, 4)},
		},
	}
	p := NewStoreBaselineProvider(fs, time.Hour)
	ctx := context.Background()

	first := p.Current(ctx)
	if first.SourceScanID != "scan-1" {
		t.Fatalf("first Current: source = %q, want scan-1", first.SourceScanID)
	}
	if fs.listCalls != 1 {
		t.Fatalf("cold cache: listCalls = %d, want 1", fs.listCalls)
	}

	// Second call inside the TTL is served from cache without touching the store.
	if got := p.Current(ctx); got.SourceScanID != "scan-1" {
		t.Errorf("cached Current: source = %q, want scan-1", got.SourceScanID)
	}
	if fs.listCalls != 1 {
		t.Errorf("warm cache: listCalls = %d, want 1", fs.listCalls)
	}

	// Force the cache stale and confirm the next call recomputes.
	p.mu.Lock()
	p.cachedAt = time.Now().Add(-2 * time.Hour)
	p.mu.Unlock()
	if got := p.Current(ctx); got.SourceScanID != "scan-1" {
		t.Errorf("recomputed Current: source = %q, want scan-1", got.SourceScanID)
	}
	if fs.listCalls != 2 {
		t.Errorf("stale cache: listCalls = %d, want 2", fs.listCalls)
	}
}
