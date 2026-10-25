package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"go.uber.org/zap"
	"golang.org/x/sync/singleflight"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// BaselineProvider supplies a current Baseline. The webhook handler caches
// the result for cacheTTL so a high-throughput admission rate does not
// rebuild the baseline on every request.
type BaselineProvider interface {
	// Current returns the latest Baseline. Implementations may return a
	// zero-value Baseline with Sufficient()==false when the store has no
	// usable data yet; callers should treat that as "allow without
	// comment."
	Current(ctx context.Context) Baseline
}

// recomputeTimeout bounds one baseline recompute. It is independent of any
// admission request so a canceled request cannot abort a recompute that other
// requests are waiting on.
const recomputeTimeout = 10 * time.Second

// StoreBaselineProvider derives the Baseline from the most recent scan
// stored in the Fleetsweeper database. The provider caches the result so
// admission traffic does not re-derive the baseline more than once per
// cacheTTL window, collapses concurrent recomputes into one store read, and
// keeps serving the last good baseline when a recompute fails.
type StoreBaselineProvider struct {
	// Log receives recompute failures. Defaults to a no-op logger.
	Log *zap.Logger
	// store is the scan database the baseline is derived from.
	store store.Store
	// ttl is how long a computed baseline is served before recomputing.
	ttl time.Duration
	// timeout bounds a single recompute.
	timeout time.Duration
	// group collapses concurrent recomputes into one.
	group singleflight.Group
	// mu guards cached and cachedAt.
	mu sync.Mutex
	// cached is the last good baseline.
	cached Baseline
	// cachedAt is when the cache was last refreshed or last failed to refresh.
	cachedAt time.Time
}

// NewStoreBaselineProvider returns a provider against the given store
// with the specified cache lifetime. ttl <= 0 defaults to 60 seconds.
func NewStoreBaselineProvider(s store.Store, ttl time.Duration) *StoreBaselineProvider {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &StoreBaselineProvider{Log: zap.NewNop(), store: s, ttl: ttl, timeout: recomputeTimeout}
}

// Current returns the latest baseline, recomputing it when the cache is stale.
// When the caller's context ends before a recompute finishes, the last good
// baseline is returned instead of waiting.
func (p *StoreBaselineProvider) Current(ctx context.Context) Baseline {
	p.mu.Lock()
	cached := p.cached
	fresh := time.Since(p.cachedAt) < p.ttl
	p.mu.Unlock()
	if fresh {
		return cached
	}

	ch := p.group.DoChan("baseline", func() (any, error) {
		rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), p.timeout)
		defer cancel()
		b, err := p.recompute(rctx)

		p.mu.Lock()
		defer p.mu.Unlock()
		p.cachedAt = time.Now()
		if err != nil {
			p.Log.Warn("admission baseline recompute failed: serving last good baseline", zap.Error(err))
			return p.cached, nil
		}
		p.cached = b
		return b, nil
	})
	select {
	case res := <-ch:
		b, _ := res.Val.(Baseline)
		return b
	case <-ctx.Done():
		return cached
	}
}

// recompute pulls the most recent scan and tallies the fractions the built-in
// checks rely on. Each cluster contributes its own counts: container fractions
// from workload-security are measured against that cluster's image-audit
// container count, and a scanner result whose State is not OK contributes
// nothing. A store error is returned so the caller can keep the last good
// baseline; an empty store is not an error.
func (p *StoreBaselineProvider) recompute(ctx context.Context) (Baseline, error) {
	scans, err := p.store.ListScans(ctx, 1)
	if err != nil {
		return Baseline{}, fmt.Errorf("list scans: %w", err)
	}
	if len(scans) == 0 {
		return Baseline{}, nil
	}
	results, err := p.store.GetScanResults(ctx, scans[0].ID)
	if err != nil {
		return Baseline{}, fmt.Errorf("get scan results: %w", err)
	}

	var (
		totalContainers, withDigest              int
		wsContainers, nonRoot, noPrivEsc, readRO int
		totalPods, defaultSAPods                 int
	)
	for _, perScanner := range results {
		clusterContainers := 0
		if raw, ok := perScanner["image-audit"]; ok && raw.State == scanner.StateOK {
			c, d := tallyImageAudit(raw.Data)
			clusterContainers = c
			totalContainers += c
			withDigest += d
		}
		raw, ok := perScanner["workload-security"]
		if !ok || raw.State != scanner.StateOK {
			continue
		}
		t := tallyWorkloadSec(raw.Data)
		totalPods += t.totalPods
		defaultSAPods += t.defaultSA
		if clusterContainers == 0 {
			continue
		}
		wsContainers += clusterContainers
		nonRoot += max(clusterContainers-t.runAsRoot, 0)
		noPrivEsc += max(clusterContainers-t.allowPrivEsc, 0)
		readRO += max(clusterContainers-t.noReadOnlyRoot, 0)
	}

	return Baseline{
		SourceScanID:                  scans[0].ID,
		SampleContainers:              totalContainers,
		SamplePods:                    totalPods,
		DigestPinFraction:             floatRatio(withDigest, totalContainers),
		NonRootFraction:               floatRatio(nonRoot, wsContainers),
		NoPrivilegeEscalationFraction: floatRatio(noPrivEsc, wsContainers),
		ReadOnlyRootFSFraction:        floatRatio(readRO, wsContainers),
		NamedServiceAccountFraction:   floatRatio(totalPods-defaultSAPods, totalPods),
	}, nil
}

// floatRatio returns numerator/denominator as a fraction, clamped to [0, 1].
func floatRatio(n, d int) float64 {
	if d <= 0 {
		return 0
	}
	r := float64(n) / float64(d)
	if r < 0 {
		return 0
	}
	if r > 1 {
		return 1
	}
	return r
}

// tallyImageAudit extracts (total_containers, with_digest_pin) from the
// image-audit scanner's Data payload.
func tallyImageAudit(data any) (total int, digestPinned int) {
	b, err := json.Marshal(data)
	if err != nil {
		return 0, 0
	}
	var m struct {
		TotalContainers int `json:"total_containers"`
		NoDigest        int `json:"no_digest"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return 0, 0
	}
	if m.TotalContainers <= 0 {
		return 0, 0
	}
	return m.TotalContainers, m.TotalContainers - m.NoDigest
}

// workloadSecTally captures the workload-sec scanner counts the
// admission baseline consumes. Keeping the shape behind a struct makes
// the recompute path readable.
type workloadSecTally struct {
	// totalPods is the count of pods scanned.
	totalPods int
	// runAsRoot is the count of containers explicitly running as UID 0.
	runAsRoot int
	// allowPrivEsc is the count of containers with allowPrivilegeEscalation
	// implicitly or explicitly true.
	allowPrivEsc int
	// noReadOnlyRoot is the count of containers without
	// readOnlyRootFilesystem=true.
	noReadOnlyRoot int
	// defaultSA is the count of pods running under the default ServiceAccount.
	defaultSA int
}

// tallyWorkloadSec extracts the workload-sec aggregate counts from the
// scanner's Data payload.
func tallyWorkloadSec(data any) workloadSecTally {
	b, err := json.Marshal(data)
	if err != nil {
		return workloadSecTally{}
	}
	var m struct {
		TotalPods                int `json:"total_pods"`
		RunAsRootContainers      int `json:"run_as_root_containers"`
		AllowPrivilegeEscalation int `json:"allow_privilege_escalation"`
		NoReadOnlyRoot           int `json:"no_read_only_root"`
		DefaultServiceAccount    int `json:"default_service_account_pods"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return workloadSecTally{}
	}
	return workloadSecTally{
		totalPods:      m.TotalPods,
		runAsRoot:      m.RunAsRootContainers,
		allowPrivEsc:   m.AllowPrivilegeEscalation,
		noReadOnlyRoot: m.NoReadOnlyRoot,
		defaultSA:      m.DefaultServiceAccount,
	}
}
