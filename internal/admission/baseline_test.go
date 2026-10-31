package admission

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
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
	// results is returned by GetScanResults for a scan not in byScan.
	results map[string]map[string]scanner.Result
	// byScan holds per-scan results keyed by scan ID.
	byScan map[string]map[string]map[string]scanner.Result
	// failScan makes GetScanResults fail for this scan ID.
	failScan string
	// resultsErr is returned alongside results.
	resultsErr error
	// delay makes ListScans slow so concurrent callers overlap.
	delay time.Duration
	// mu guards every field above and listCalls.
	mu sync.Mutex
	// listCalls counts ListScans invocations so cache behavior is observable.
	listCalls int
}

// ListScans returns up to limit canned scan records and increments the call counter.
func (f *fakeStore) ListScans(_ context.Context, limit int) ([]store.ScanRecord, error) {
	f.mu.Lock()
	f.listCalls++
	delay := f.delay
	scans, err := f.scans, f.scansErr
	f.mu.Unlock()
	time.Sleep(delay)
	if limit > 0 && len(scans) > limit {
		scans = scans[:limit]
	}
	return scans, err
}

// GetScanResults returns the canned per-cluster scanner results.
func (f *fakeStore) GetScanResults(_ context.Context, id string) (map[string]map[string]scanner.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id == f.failScan {
		return nil, errors.New("scan results unavailable")
	}
	if r, ok := f.byScan[id]; ok {
		return r, nil
	}
	return f.results, f.resultsErr
}

// calls returns the ListScans call count.
func (f *fakeStore) calls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.listCalls
}

// imageAuditData builds an image-audit scanner Data payload.
func imageAuditData(totalContainers, noDigest int) scanner.Result {
	return scanner.Result{Scanner: "image-audit", Data: map[string]any{
		"total_containers": totalContainers,
		"no_digest":        noDigest,
	}}
}

// workloadSecData builds a workload-security scanner Data payload.
func workloadSecData(totalPods, containers, nonRoot, allowPrivEsc, noReadOnly, defaultSA int) scanner.Result {
	return scanner.Result{Scanner: "workload-security", Data: map[string]any{
		"total_pods":                   totalPods,
		"baseline_containers":          containers,
		"run_as_non_root_containers":   nonRoot,
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
				"baseline_containers":          40,
				"run_as_root_containers":       8,
				"run_as_non_root_containers":   30,
				"allow_privilege_escalation":   10,
				"no_read_only_root":            12,
				"default_service_account_pods": 5,
			},
			WantResult: workloadSecTally{
				totalPods: 20, containers: 40, nonRoot: 30, allowPrivEsc: 10, noReadOnlyRoot: 12,
				defaultSA: 5,
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
		WantErr      bool
	}{
		{ // Test 0: Both scanners present produce every fraction.
			Store: &fakeStore{
				scans: oneScan,
				results: map[string]map[string]scanner.Result{
					"clusterA": {
						"image-audit":       imageAuditData(40, 4),
						"workload-security": workloadSecData(20, 40, 32, 10, 12, 5),
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
		{ // Test 3: ListScans error is returned.
			Store:   &fakeStore{scansErr: errBoom},
			WantErr: true,
		},
		{ // Test 4: No scans yields the zero baseline.
			Store:        &fakeStore{scans: nil},
			WantBaseline: Baseline{},
		},
		{ // Test 5: GetScanResults error is returned.
			Store:   &fakeStore{scans: oneScan, resultsErr: errBoom},
			WantErr: true,
		},
		{ // Test 6: Two clusters aggregate per-cluster counts. A has 40 containers
			// (4 unpinned, 32 non-root, 10 priv-esc, 12 writable root) and 20 pods (5
			// default SA). B has 10 containers (0 unpinned, 0 non-root, 0 priv-esc,
			// 10 writable root) and 10 pods (0 default SA). Digest (36+10)/50=0.92,
			// non-root (32+0)/50=0.64, no-priv-esc (30+10)/50=0.8, read-only
			// (28+0)/50=0.56, named SA (15+10)/30.
			Store: &fakeStore{
				scans: oneScan,
				results: map[string]map[string]scanner.Result{
					"clusterA": {
						"image-audit":       imageAuditData(40, 4),
						"workload-security": workloadSecData(20, 40, 32, 10, 12, 5),
					},
					"clusterB": {
						"image-audit":       imageAuditData(10, 0),
						"workload-security": workloadSecData(10, 10, 0, 0, 10, 0),
					},
				},
			},
			WantBaseline: Baseline{
				SampleContainers:              50,
				SamplePods:                    30,
				DigestPinFraction:             0.92,
				NonRootFraction:               0.64,
				NoPrivilegeEscalationFraction: 0.8,
				ReadOnlyRootFSFraction:        0.56,
				NamedServiceAccountFraction:   25.0 / 30.0,
				SourceScanID:                  "scan-1",
			},
		},
		{ // Test 7: A degraded workload-security result on B is skipped, so B adds
			// containers to the digest fraction only. Container fractions use A's 40.
			Store: &fakeStore{
				scans: oneScan,
				results: map[string]map[string]scanner.Result{
					"clusterA": {
						"image-audit":       imageAuditData(40, 4),
						"workload-security": workloadSecData(20, 40, 32, 10, 12, 5),
					},
					"clusterB": {
						"image-audit":       imageAuditData(10, 0),
						"workload-security": degraded(workloadSecData(10, 10, 0, 0, 10, 0)),
					},
				},
			},
			WantBaseline: Baseline{
				SampleContainers:              50,
				SamplePods:                    20,
				DigestPinFraction:             0.92,
				NonRootFraction:               0.8,
				NoPrivilegeEscalationFraction: 0.75,
				ReadOnlyRootFSFraction:        0.7,
				NamedServiceAccountFraction:   0.75,
				SourceScanID:                  "scan-1",
			},
		},
		{ // Test 8: An errored image-audit result on B removes B's containers from the
			// digest fraction only. B's workload-security counts still feed the container
			// fractions and its pods the service account fraction.
			Store: &fakeStore{
				scans: oneScan,
				results: map[string]map[string]scanner.Result{
					"clusterA": {
						"image-audit":       imageAuditData(40, 4),
						"workload-security": workloadSecData(20, 40, 32, 10, 12, 5),
					},
					"clusterB": {
						"image-audit":       errored(imageAuditData(10, 0)),
						"workload-security": workloadSecData(10, 10, 0, 0, 10, 0),
					},
				},
			},
			WantBaseline: Baseline{
				SampleContainers:              40,
				SamplePods:                    30,
				DigestPinFraction:             0.9,
				NonRootFraction:               0.64,
				NoPrivilegeEscalationFraction: 0.8,
				ReadOnlyRootFSFraction:        0.56,
				NamedServiceAccountFraction:   25.0 / 30.0,
				SourceScanID:                  "scan-1",
			},
		},
		{ // Test 9: Unknown containers count as not non-root, so 20 explicit non-root of
			// 40 is half even with no container running as root.
			Store: &fakeStore{
				scans: oneScan,
				results: map[string]map[string]scanner.Result{
					"clusterA": {
						"image-audit":       imageAuditData(40, 0),
						"workload-security": workloadSecData(20, 40, 20, 0, 0, 0),
					},
				},
			},
			WantBaseline: Baseline{
				SampleContainers:              40,
				SamplePods:                    20,
				DigestPinFraction:             1,
				NonRootFraction:               0.5,
				NoPrivilegeEscalationFraction: 1,
				ReadOnlyRootFSFraction:        1,
				NamedServiceAccountFraction:   1,
				SourceScanID:                  "scan-1",
			},
		},
		{ // Test 10: Container fractions use baseline containers, not the image-audit
			// total, which also counts ephemeral containers.
			Store: &fakeStore{
				scans: oneScan,
				results: map[string]map[string]scanner.Result{
					"clusterA": {
						"image-audit":       imageAuditData(50, 0),
						"workload-security": workloadSecData(20, 40, 40, 10, 20, 0),
					},
				},
			},
			WantBaseline: Baseline{
				SampleContainers:              50,
				SamplePods:                    20,
				DigestPinFraction:             1,
				NonRootFraction:               1,
				NoPrivilegeEscalationFraction: 0.75,
				ReadOnlyRootFSFraction:        0.5,
				NamedServiceAccountFraction:   1,
				SourceScanID:                  "scan-1",
			},
		},
	}
	for testNum, test := range tests {
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			p := NewStoreBaselineProvider(test.Store, time.Minute)
			got, err := p.recompute(context.Background())
			if (err != nil) != test.WantErr {
				t.Fatalf("test %d: err = %v, wantErr %v", testNum, err, test.WantErr)
			}
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
	if got := fs.calls(); got != 1 {
		t.Fatalf("cold cache: listCalls = %d, want 1", got)
	}

	// Second call inside the TTL is served from cache without touching the store.
	if got := p.Current(ctx); got.SourceScanID != "scan-1" {
		t.Errorf("cached Current: source = %q, want scan-1", got.SourceScanID)
	}
	if got := fs.calls(); got != 1 {
		t.Errorf("warm cache: listCalls = %d, want 1", got)
	}

	// Force the cache stale and confirm the next call recomputes.
	p.mu.Lock()
	p.cachedAt = time.Now().Add(-2 * time.Hour)
	p.mu.Unlock()
	if got := p.Current(ctx); got.SourceScanID != "scan-1" {
		t.Errorf("recomputed Current: source = %q, want scan-1", got.SourceScanID)
	}
	if got := fs.calls(); got != 2 {
		t.Errorf("stale cache: listCalls = %d, want 2", got)
	}
}

// degraded marks a scanner result as degraded.
func degraded(r scanner.Result) scanner.Result {
	r.State, r.Reason = scanner.StateDegraded, "partial list"
	return r
}

// errored marks a scanner result as errored.
func errored(r scanner.Result) scanner.Result {
	r.State, r.Reason = scanner.StateErrored, "timeout"
	return r
}

// expire marks the provider's cache stale.
func expire(p *StoreBaselineProvider) {
	p.mu.Lock()
	p.cachedAt = time.Now().Add(-2 * time.Hour)
	p.mu.Unlock()
}

// TestStoreBaselineProviderKeepsLastGood verifies a failing store serves the
// last good baseline instead of caching an empty one.
func TestStoreBaselineProviderKeepsLastGood(t *testing.T) {
	t.Parallel()
	fs := &fakeStore{
		scans: []store.ScanRecord{{ID: "scan-1"}},
		results: map[string]map[string]scanner.Result{
			"clusterA": {"image-audit": imageAuditData(40, 4)},
		},
	}
	p := NewStoreBaselineProvider(fs, time.Hour)
	ctx := context.Background()
	good := p.Current(ctx)
	if good.SourceScanID != "scan-1" || good.SampleContainers != 40 {
		t.Fatalf("first Current = %+v", good)
	}

	fs.mu.Lock()
	fs.scansErr = errors.New("db down")
	fs.mu.Unlock()
	expire(p)

	got := p.Current(ctx)
	if diff := cmp.Diff(good, got); diff != "" {
		t.Errorf("failed recompute should serve last good (-want +got):\n%s", diff)
	}
	if got := fs.calls(); got != 2 {
		t.Errorf("listCalls = %d, want 2", got)
	}
	// The failure refreshes cachedAt, so the next call inside the TTL does not
	// retry the failing store.
	p.Current(ctx)
	if got := fs.calls(); got != 2 {
		t.Errorf("listCalls after failure = %d, want 2", got)
	}
}

// TestStoreBaselineProviderSingleflight verifies 50 concurrent callers after
// the TTL expires trigger exactly one store read.
func TestStoreBaselineProviderSingleflight(t *testing.T) {
	t.Parallel()
	fs := &fakeStore{
		scans: []store.ScanRecord{{ID: "scan-1"}},
		results: map[string]map[string]scanner.Result{
			"clusterA": {"image-audit": imageAuditData(40, 4)},
		},
		delay: 100 * time.Millisecond,
	}
	p := NewStoreBaselineProvider(fs, time.Hour)

	var wg sync.WaitGroup
	start := make(chan struct{})
	got := make([]Baseline, 50)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			got[i] = p.Current(context.Background())
		}(i)
	}
	close(start)
	wg.Wait()

	if n := fs.calls(); n != 1 {
		t.Errorf("listCalls = %d, want 1", n)
	}
	for i, b := range got {
		if b.SourceScanID != "scan-1" {
			t.Errorf("caller %d got %+v", i, b)
		}
	}
}

// TestStoreBaselineProviderCallerCancel verifies a caller whose context ends
// gets the cached baseline without waiting, while the recompute completes for
// everyone else.
func TestStoreBaselineProviderCallerCancel(t *testing.T) {
	t.Parallel()
	fs := &fakeStore{
		scans: []store.ScanRecord{{ID: "scan-1"}},
		results: map[string]map[string]scanner.Result{
			"clusterA": {"image-audit": imageAuditData(40, 4)},
		},
		delay: 200 * time.Millisecond,
	}
	p := NewStoreBaselineProvider(fs, time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	if got := p.Current(ctx); got.SourceScanID != "" {
		t.Errorf("canceled caller should get the empty cache, got %+v", got)
	}
	if got := p.Current(context.Background()); got.SourceScanID != "scan-1" {
		t.Errorf("waiting caller should get the recomputed baseline, got %+v", got)
	}
	if n := fs.calls(); n != 1 {
		t.Errorf("listCalls = %d, want 1", n)
	}
}

// TestStoreBaselineProviderHistory verifies the provider derives one baseline per recent scan up
// to Depth, newest first, and fails the whole recompute when an earlier scan cannot be read.
func TestStoreBaselineProviderHistory(t *testing.T) {
	t.Parallel()
	digestScan := func(noDigest int) map[string]map[string]scanner.Result {
		r := imageAuditData(100, noDigest)
		r.State = scanner.StateOK
		return map[string]map[string]scanner.Result{"a": {"image-audit": r}}
	}
	scans := []store.ScanRecord{{ID: "s3"}, {ID: "s2"}, {ID: "s1"}}
	byScan := map[string]map[string]map[string]scanner.Result{
		"s3": digestScan(5), "s2": digestScan(20), "s1": digestScan(50),
	}
	type point struct {
		ID     string
		Digest float64
	}
	tests := []struct {
		Store    *fakeStore
		Depth    int
		WantCur  point
		WantPrev []point
		WantErr  bool
	}{{ // Test 0: Depth 3 loads the latest scan and the two before it, newest first.
		Store: &fakeStore{scans: scans, byScan: byScan}, Depth: 3,
		WantCur: point{"s3", 0.95}, WantPrev: []point{{"s2", 0.8}, {"s1", 0.5}},
	}, { // Test 1: Depth 1 loads the latest scan alone.
		Store: &fakeStore{scans: scans, byScan: byScan}, Depth: 1, WantCur: point{"s3", 0.95},
	}, { // Test 2: A store with fewer scans than Depth returns what it has.
		Store: &fakeStore{scans: scans[:2], byScan: byScan}, Depth: 5,
		WantCur: point{"s3", 0.95}, WantPrev: []point{{"s2", 0.8}},
	}, { // Test 3: Depth 0 reads as 1.
		Store: &fakeStore{scans: scans, byScan: byScan}, Depth: 0, WantCur: point{"s3", 0.95},
	}, { // Test 4: An unreadable earlier scan fails the recompute.
		Store: &fakeStore{scans: scans, byScan: byScan, failScan: "s1"}, Depth: 3, WantErr: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			p := NewStoreBaselineProvider(test.Store, time.Minute)
			p.Depth = test.Depth
			b, err := p.recompute(context.Background())
			if (err != nil) != test.WantErr {
				t.Fatalf("err = %v, want error %v", err, test.WantErr)
			}
			if test.WantErr {
				return
			}
			if diff := cmp.Diff(test.WantCur, point{b.SourceScanID, b.DigestPinFraction}); diff != "" {
				t.Errorf("current mismatch (-want +got):\n%s", diff)
			}
			var prev []point
			for _, pb := range b.Previous {
				prev = append(prev, point{pb.SourceScanID, pb.DigestPinFraction})
			}
			if diff := cmp.Diff(test.WantPrev, prev, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("previous mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNewStoreBaselineProviderDepth verifies the provider defaults to the handler's stability
// window.
func TestNewStoreBaselineProviderDepth(t *testing.T) {
	t.Parallel()
	if got := NewStoreBaselineProvider(&fakeStore{}, 0).Depth; got != DefaultStableScans {
		t.Errorf("Depth = %d, want %d", got, DefaultStableScans)
	}
}

// TestPinnedBaselineProvider verifies a pinned provider serves its baseline marked Pinned with
// no history, whatever it was given.
func TestPinnedBaselineProvider(t *testing.T) {
	t.Parallel()
	in := Baseline{SamplePods: 20, SampleContainers: 40, DigestPinFraction: 0.9,
		Previous: []Baseline{{DigestPinFraction: 0.1}}}
	got := NewPinnedBaselineProvider(in).Current(context.Background())
	want := Baseline{SamplePods: 20, SampleContainers: 40, DigestPinFraction: 0.9, Pinned: true}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("baseline mismatch (-want +got):\n%s", diff)
	}
}

// TestLoadBaselineFile verifies a pinned baseline file loads in the export format and that a
// typo, an out-of-range fraction, or a negative count is rejected.
func TestLoadBaselineFile(t *testing.T) {
	t.Parallel()
	valid := "sample_pods: 20\nsample_containers: 40\ndigest_pin_fraction: 0.9\n" +
		"non_root_fraction: 0.8\nno_privilege_escalation_fraction: 0.75\n" +
		"named_service_account_fraction: 0.7\nread_only_root_fs_fraction: 0.6\nsource_scan_id: s1\n"
	tests := []struct {
		Body         string
		Missing      bool
		WantBaseline Baseline
		Want         error
	}{{ // Test 0: The export format loads every field.
		Body: valid,
		WantBaseline: Baseline{SamplePods: 20, SampleContainers: 40, DigestPinFraction: 0.9,
			NonRootFraction: 0.8, NoPrivilegeEscalationFraction: 0.75, NamedServiceAccountFraction: 0.7,
			ReadOnlyRootFSFraction: 0.6, SourceScanID: "s1"},
	}, { // Test 1: An unknown field is rejected.
		Body: valid + "digest_pin_fracton: 0.9\n", Want: ErrBaselineFile,
	}, { // Test 2: A fraction above 1 is rejected.
		Body: "sample_pods: 20\nnon_root_fraction: 1.5\n", Want: ErrBaselineFile,
	}, { // Test 3: A negative fraction is rejected.
		Body: "read_only_root_fs_fraction: -0.1\n", Want: ErrBaselineFile,
	}, { // Test 4: NaN is rejected.
		Body: "digest_pin_fraction: .nan\n", Want: ErrBaselineFile,
	}, { // Test 5: A negative sample count is rejected.
		Body: "sample_containers: -1\n", Want: ErrBaselineFile,
	}, { // Test 6: A missing file is rejected.
		Missing: true, Want: ErrBaselineFile,
	}, { // Test 7: A file that is not YAML is rejected.
		Body: "{not: [yaml", Want: ErrBaselineFile,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "baseline.yaml")
			if !test.Missing {
				if err := os.WriteFile(path, []byte(test.Body), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
			}
			got, err := LoadBaselineFile(path)
			if !errors.Is(err, test.Want) {
				t.Fatalf("err = %v, want %v", err, test.Want)
			}
			if diff := cmp.Diff(test.WantBaseline, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("baseline mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
