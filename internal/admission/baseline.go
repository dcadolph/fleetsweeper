package admission

import (
	"context"
	"encoding/json"
	"sync"
	"time"

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

// StoreBaselineProvider derives the Baseline from the most recent scan
// stored in the Fleetsweeper database. The provider caches the result so
// admission traffic does not re-derive the baseline more than once per
// cacheTTL window.
type StoreBaselineProvider struct {
	store    store.Store
	ttl      time.Duration
	mu       sync.Mutex
	cached   Baseline
	cachedAt time.Time
}

// NewStoreBaselineProvider returns a provider against the given store
// with the specified cache lifetime. ttl <= 0 defaults to 60 seconds.
func NewStoreBaselineProvider(s store.Store, ttl time.Duration) *StoreBaselineProvider {
	if ttl <= 0 {
		ttl = 60 * time.Second
	}
	return &StoreBaselineProvider{store: s, ttl: ttl}
}

// Current returns the latest baseline, recomputing it when the cache is stale.
func (p *StoreBaselineProvider) Current(ctx context.Context) Baseline {
	p.mu.Lock()
	if time.Since(p.cachedAt) < p.ttl {
		out := p.cached
		p.mu.Unlock()
		return out
	}
	p.mu.Unlock()

	b := p.recompute(ctx)

	p.mu.Lock()
	p.cached = b
	p.cachedAt = time.Now()
	p.mu.Unlock()
	return b
}

// recompute pulls the most recent scan, walks its image-audit and
// workload-sec outputs, and tallies the fractions the built-in checks rely on.
func (p *StoreBaselineProvider) recompute(ctx context.Context) Baseline {
	scans, err := p.store.ListScans(ctx, 1)
	if err != nil || len(scans) == 0 {
		return Baseline{}
	}
	results, err := p.store.GetScanResults(ctx, scans[0].ID)
	if err != nil {
		return Baseline{}
	}

	b := Baseline{SourceScanID: scans[0].ID}
	totalContainers := 0
	withDigest := 0
	withNonRoot := 0
	noPrivEsc := 0
	readOnlyFS := 0
	totalPods := 0
	defaultSAPods := 0

	for _, perScanner := range results {
		if raw, ok := perScanner["image-audit"]; ok {
			c, d := tallyImageAudit(raw.Data)
			totalContainers += c
			withDigest += d
		}
		if raw, ok := perScanner["workload-security"]; ok {
			t := tallyWorkloadSec(raw.Data)
			totalPods += t.totalPods
			withNonRoot += (totalContainers - t.runAsRoot)
			noPrivEsc += (totalContainers - t.allowPrivEsc)
			readOnlyFS += (totalContainers - t.noReadOnlyRoot)
			defaultSAPods += t.defaultSA
		}
	}

	b.SampleContainers = totalContainers
	b.SamplePods = totalPods
	if totalContainers > 0 {
		b.DigestPinFraction = floatRatio(withDigest, totalContainers)
		b.NonRootFraction = floatRatio(withNonRoot, totalContainers)
		b.NoPrivilegeEscalationFraction = floatRatio(noPrivEsc, totalContainers)
		b.ReadOnlyRootFSFraction = floatRatio(readOnlyFS, totalContainers)
	}
	if totalPods > 0 {
		b.NamedServiceAccountFraction = floatRatio(totalPods-defaultSAPods, totalPods)
	}
	return b
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
