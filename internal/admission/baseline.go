package admission

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.yaml.in/yaml/v3"
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

// DefaultStableScans is how many consecutive recent scans a norm must hold before enforce
// mode denies on it, and how many scans a StoreBaselineProvider derives baselines from.
const DefaultStableScans = 3

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
	// Depth is how many recent scans Current derives baselines from, the latest included. The
	// handler's stability gate needs it to match Handler.StableScans. Defaults to
	// DefaultStableScans; values below 1 read as 1. Set it before the first Current call.
	Depth int
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
	return &StoreBaselineProvider{
		Log: zap.NewNop(), Depth: DefaultStableScans, store: s, ttl: ttl, timeout: recomputeTimeout,
	}
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

// recompute derives the baseline of the most recent scan and, in Previous, the baselines of up
// to Depth-1 scans before it. A store error is returned so the caller can keep the last good
// baseline; an empty store is not an error.
func (p *StoreBaselineProvider) recompute(ctx context.Context) (Baseline, error) {
	scans, err := p.store.ListScans(ctx, max(p.Depth, 1))
	if err != nil {
		return Baseline{}, fmt.Errorf("list scans: %w", err)
	}
	if len(scans) == 0 {
		return Baseline{}, nil
	}
	cur, err := p.scanBaseline(ctx, scans[0].ID)
	if err != nil {
		return Baseline{}, err
	}
	for _, rec := range scans[1:] {
		prev, err := p.scanBaseline(ctx, rec.ID)
		if err != nil {
			return Baseline{}, err
		}
		cur.Previous = append(cur.Previous, prev)
	}
	return cur, nil
}

// scanBaseline tallies the fractions the built-in checks rely on from one scan. Each cluster
// contributes its own counts: the digest fraction comes from image-audit, the other container
// fractions from workload-security over its baseline containers (init and regular, as admission
// sees them), and a scanner result whose State is not OK contributes nothing.
func (p *StoreBaselineProvider) scanBaseline(ctx context.Context, scanID string) (Baseline, error) {
	results, err := p.store.GetScanResults(ctx, scanID)
	if err != nil {
		return Baseline{}, fmt.Errorf("get scan results %s: %w", scanID, err)
	}

	var (
		totalContainers, withDigest              int
		wsContainers, nonRoot, noPrivEsc, readRO int
		totalPods, defaultSAPods                 int
	)
	for _, perScanner := range results {
		if raw, ok := perScanner["image-audit"]; ok && raw.State == scanner.StateOK {
			c, d := tallyImageAudit(raw.Data)
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
		if t.containers <= 0 {
			continue
		}
		wsContainers += t.containers
		nonRoot += min(max(t.nonRoot, 0), t.containers)
		noPrivEsc += max(t.containers-t.allowPrivEsc, 0)
		readRO += max(t.containers-t.noReadOnlyRoot, 0)
	}

	return Baseline{
		SourceScanID:                  scanID,
		SampleContainers:              totalContainers,
		SamplePods:                    totalPods,
		DigestPinFraction:             floatRatio(withDigest, totalContainers),
		NonRootFraction:               floatRatio(nonRoot, wsContainers),
		NoPrivilegeEscalationFraction: floatRatio(noPrivEsc, wsContainers),
		ReadOnlyRootFSFraction:        floatRatio(readRO, wsContainers),
		NamedServiceAccountFraction:   floatRatio(totalPods-defaultSAPods, totalPods),
	}, nil
}

// PinnedBaselineProvider serves one fixed Baseline an operator loaded from a file instead of
// deriving it from the store.
type PinnedBaselineProvider struct {
	// baseline is the pinned norm, marked Pinned.
	baseline Baseline
}

// NewPinnedBaselineProvider returns a provider that always serves b, marked Pinned.
func NewPinnedBaselineProvider(b Baseline) *PinnedBaselineProvider {
	b.Pinned = true
	b.Previous = nil
	return &PinnedBaselineProvider{baseline: b}
}

// Current returns the pinned baseline.
func (p *PinnedBaselineProvider) Current(context.Context) Baseline {
	return p.baseline
}

// LoadBaselineFile reads a baseline in the `baseline export` YAML format. Unknown fields,
// fractions outside [0, 1], and negative sample counts are errors, so a typo cannot pin a norm
// the operator did not mean.
func LoadBaselineFile(path string) (Baseline, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Baseline{}, fmt.Errorf("%w: %w", ErrBaselineFile, err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(body))
	dec.KnownFields(true)
	var b Baseline
	if err := dec.Decode(&b); err != nil {
		return Baseline{}, fmt.Errorf("%w: parse %s: %w", ErrBaselineFile, path, err)
	}
	if b.SamplePods < 0 || b.SampleContainers < 0 {
		return Baseline{}, fmt.Errorf("%w: %s: sample counts must not be negative", ErrBaselineFile, path)
	}
	fractions := []struct {
		name string
		v    float64
	}{
		{"digest_pin_fraction", b.DigestPinFraction},
		{"non_root_fraction", b.NonRootFraction},
		{"no_privilege_escalation_fraction", b.NoPrivilegeEscalationFraction},
		{"named_service_account_fraction", b.NamedServiceAccountFraction},
		{"read_only_root_fs_fraction", b.ReadOnlyRootFSFraction},
	}
	for _, f := range fractions {
		if !(f.v >= 0 && f.v <= 1) {
			return Baseline{}, fmt.Errorf("%w: %s: %s is %v, want a value in [0, 1]", ErrBaselineFile, path, f.name, f.v)
		}
	}
	return b, nil
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
	// containers is the count of init and regular containers, the denominator of every
	// container fraction except the digest one.
	containers int
	// nonRoot is the count of containers explicitly non-root.
	nonRoot int
	// allowPrivEsc is the count of containers that may gain privileges.
	allowPrivEsc int
	// noReadOnlyRoot is the count of containers without a read-only root filesystem.
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
		BaselineContainers       int `json:"baseline_containers"`
		RunAsNonRootContainers   int `json:"run_as_non_root_containers"`
		AllowPrivilegeEscalation int `json:"allow_privilege_escalation"`
		NoReadOnlyRoot           int `json:"no_read_only_root"`
		DefaultServiceAccount    int `json:"default_service_account_pods"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return workloadSecTally{}
	}
	return workloadSecTally{
		totalPods:      m.TotalPods,
		containers:     m.BaselineContainers,
		nonRoot:        m.RunAsNonRootContainers,
		allowPrivEsc:   m.AllowPrivilegeEscalation,
		noReadOnlyRoot: m.NoReadOnlyRoot,
		defaultSA:      m.DefaultServiceAccount,
	}
}
