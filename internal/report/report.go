// Package report builds the fleet comparison report from per-cluster scanner results,
// including divergences, findings, scores, outliers, and trends.
package report

import (
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Severity levels for divergences.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Category groups related scanners for report organization.
type Category struct {
	// Name is the category display name.
	Name string `json:"name"`
	// Scanners lists the scanner names in this category.
	Scanners []string `json:"scanners"`
}

// Categories returns the scanner groupings used in reports.
func Categories() []Category {
	return []Category{
		{Name: "Cluster Info", Scanners: []string{"version", "namespaces", "crds", "deprecated-apis", "geo"}},
		{Name: "Workloads", Scanners: []string{"services", "ingresses", "image-audit", "workload-coverage"}},
		{Name: "Health & Resources", Scanners: []string{
			"node-health", "metrics", "resources", "resource-quotas", "cluster-info",
		}},
		{Name: "Security & Access", Scanners: []string{
			"workload-security", "rbac-audit", "rbac", "security", "network-policies", "vulnerabilities", "policy-reports",
			"certs", "admission",
		}},
		{Name: "Events & Logs", Scanners: []string{"events"}},
	}
}

// CategoryOf returns the name of the category that holds scanner, or "Other" when none does.
func CategoryOf(scanner string) string {
	for _, c := range Categories() {
		if slices.Contains(c.Scanners, scanner) {
			return c.Name
		}
	}
	return "Other"
}

// Report is the top-level output structure.
type Report struct {
	// Timestamp is when the scan was executed.
	Timestamp string `json:"timestamp"`
	// Clusters lists the kubeconfig contexts that were scanned.
	Clusters []string `json:"clusters"`
	// Categories groups sections by functional area.
	Categories []Category `json:"categories"`
	// Sections holds per-scanner comparison results keyed by scanner name.
	Sections map[string]*SectionReport `json:"sections"`
	// Summary holds fleet-wide summary statistics.
	Summary Summary `json:"summary"`
	// Findings lists human-readable issues discovered across the fleet.
	Findings []Finding `json:"findings"`
	// ClusterHealths holds per-cluster health summaries.
	ClusterHealths []ClusterHealth `json:"cluster_healths"`
	// Outliers lists clusters that deviate from fleet norms. Fleets of
	// minMADSample clusters or more use MAD. Fleets of minMajoritySample to
	// minMADSample-1 use the leave-one-out majority diff, whose results are
	// marked LimitedSample. Smaller fleets get none and a line in Notes.
	Outliers []OutlierResult `json:"outliers,omitempty"`
	// Distributions holds the population behind every field the fleet and
	// cohort detectors evaluated, fleet scope first, most deviant first.
	Distributions []Distribution `json:"distributions,omitempty"`
	// DeviationMass sums, per cluster, the capped |z| of its numeric values
	// across the fleet-scope distributions. Clusters at zero are left out.
	DeviationMass map[string]float64 `json:"deviation_mass,omitempty"`
	// ScoreAttribution is the full cost ledger behind FleetScore.
	ScoreAttribution *ScoreAttribution `json:"score_attribution,omitempty"`
	// Capacity holds smart capacity analysis per cluster, correlating
	// utilization, pressure, events, and headroom.
	Capacity []CapacityAnalysis `json:"capacity,omitempty"`
	// FleetScore is the single 0-100 indicator of overall fleet health,
	// suitable as a hero number on a status TV. Populated by Build.
	FleetScore FleetScore `json:"fleet_score"`
	// Cohorts partitions the fleet into groups of similar clusters and
	// reports within-cohort outliers. Cohorts come from user-supplied
	// cluster tags when present, otherwise from agglomerative clustering
	// on scanner-derived features.
	Cohorts []CohortSummary `json:"cohorts,omitempty"`
	// Degraded lists scanner runs that did not return complete, trustworthy
	// data for a cluster, so the report surfaces reduced coverage instead of
	// reading a failed or forbidden scan as a clean, zero-resource result.
	Degraded []ScannerStatus `json:"degraded,omitempty"`
	// Incidents groups related findings by shared root cause so operators read
	// one incident instead of a flat list of correlated symptoms.
	Incidents []Incident `json:"incidents,omitempty"`
	// Brief is a short, deterministic executive summary of this report.
	Brief Brief `json:"brief"`
	// Notes explain analysis the report could not run, such as outlier
	// detection on a fleet too small to have a norm.
	Notes []string `json:"notes,omitempty"`
}

// ScannerStatus records a scanner run that did not return complete,
// trustworthy data for one cluster. It lets the report show degraded coverage
// ("3 of 24 scanners degraded on cluster X") instead of silently treating a
// failed or forbidden scan as a clean result.
type ScannerStatus struct {
	// Cluster is the cluster the scanner ran against.
	Cluster string `json:"cluster"`
	// Scanner is the scanner name.
	Scanner string `json:"scanner"`
	// State is "degraded", "errored", or "unavailable".
	State string `json:"state"`
	// Reason is a short explanation of why the data is not fully trustworthy.
	Reason string `json:"reason,omitempty"`
}

// BuildOptions controls report generation behavior.
type BuildOptions struct {
	// OutlierThreshold controls outlier sensitivity (standard deviations).
	// Lower values flag more outliers. Default is 3.5.
	OutlierThreshold float64
	// Groups maps group name to cluster names for group-aware analysis.
	Groups map[string][]string
	// ClusterTags maps cluster name to a cohort tag value. When non-empty,
	// tagged clusters land in tagged cohorts instead of being auto-grouped.
	// Untagged clusters still get auto-cohorted.
	ClusterTags map[string]string
	// Timestamp is when the scan behind the report ran. A report rebuilt from a stored scan
	// passes that scan's time, so rebuilding it later yields the same report. Zero means now.
	Timestamp time.Time
}

// Summary holds fleet-wide statistics.
type Summary struct {
	// ClusterCount is the number of clusters scanned.
	ClusterCount int `json:"cluster_count"`
	// ScannerCount is the number of scanners executed.
	ScannerCount int `json:"scanner_count"`
	// UniformCount is how many scanners found identical data across all clusters.
	UniformCount int `json:"uniform_count"`
	// DivergentCount is how many scanners found differences.
	DivergentCount int `json:"divergent_count"`
	// TotalDivergences is the total number of individual divergence points.
	TotalDivergences int `json:"total_divergences"`
	// CriticalCount is the number of critical findings.
	CriticalCount int `json:"critical_count"`
	// WarningCount is the number of warning findings.
	WarningCount int `json:"warning_count"`
}

// SectionReport holds comparison data for one scanner across all clusters.
type SectionReport struct {
	// Uniform is true when all clusters produced identical data for this scanner.
	Uniform bool `json:"uniform"`
	// PerCluster holds the raw scanner data from each cluster.
	PerCluster map[string]any `json:"per_cluster"`
	// Divergences describes specific differences found between clusters.
	Divergences []Divergence `json:"divergences,omitempty"`
}

// Divergence describes a single point of difference between clusters.
type Divergence struct {
	// Field identifies what differs (e.g. "git_version").
	Field string `json:"field"`
	// Values maps cluster name to the value it reported for this field.
	Values map[string]string `json:"values"`
}

// Build creates a Report from per-cluster scanner results. The results map is
// keyed by cluster name, then by scanner name. Options are optional; when
// omitted, defaults are used.
func Build(clusters []string, results map[string]map[string]scanner.Result, opts ...BuildOptions) *Report {
	var opt BuildOptions
	if len(opts) > 0 {
		opt = opts[0]
	}
	if opt.OutlierThreshold == 0 {
		opt.OutlierThreshold = 3.5
	}

	ts := opt.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	r := &Report{
		Timestamp: ts.UTC().Format(time.RFC3339),
		Clusters:  clusters,
		Sections:  make(map[string]*SectionReport),
	}

	scannerNames := scanner.Names(results)
	for _, name := range scannerNames {
		perCluster := make(map[string]any, len(clusters))
		for _, cluster := range clusters {
			res, ok := results[cluster][name]
			if !ok {
				continue
			}
			if res.State != scanner.StateOK {
				r.Degraded = append(r.Degraded, ScannerStatus{
					Cluster: cluster,
					Scanner: name,
					State:   string(res.State),
					Reason:  res.Reason,
				})
			}
			// A blind (errored) scanner never observed the cluster, so its
			// data must not enter the statistical population as a real zero.
			if res.Blind() {
				continue
			}
			perCluster[cluster] = res.Data
		}
		section := compare(clusters, perCluster)
		if _, identity := identityScanners[name]; identity {
			section.Uniform, section.Divergences = true, nil
		}
		r.Sections[name] = section
	}
	sortScannerStatuses(r.Degraded)

	r.Categories = buildCategories(scannerNames)
	r.Summary = buildSummary(clusters, r.Sections)

	switch {
	case len(clusters) >= minMADSample:
		r.Outliers, r.Distributions = detectOutliers(r.Clusters, r.Sections, opt.OutlierThreshold, NormScopeFleet)
	case len(clusters) >= minMajoritySample:
		r.Outliers, r.Distributions = detectMajorityOutliers(r.Clusters, r.Sections, opt.OutlierThreshold, NormScopeFleet)
	default:
		r.Notes = append(r.Notes, fmt.Sprintf(
			"Fleet-relative outlier detection needs at least %d clusters; this report has %d.",
			minMajoritySample, len(clusters),
		))
	}

	r.Capacity = analyzeCapacity(r, opt.Groups)
	var cohortDists []Distribution
	r.Cohorts, cohortDists = buildCohorts(r, opt.ClusterTags, opt.OutlierThreshold)
	applyCohortNorms(r, cohortDists)
	r.Distributions = append(r.Distributions, cohortDists...)
	sortDistributions(r.Distributions)
	r.Findings = generateFindings(r)
	r.Findings = append(r.Findings, stampFingerprints(misCohortFindings(r, opt.ClusterTags))...)
	sortFindings(r.Findings)
	r.Incidents = fuseIncidents(r.Findings)
	r.ClusterHealths = generateClusterHealth(r, r.Findings)
	Rescore(r)
	r.Brief = generateBrief(r)

	return r
}

// DegradedByCluster counts, per cluster, how many scanner runs did not return
// complete, trustworthy data. Clusters with full coverage are omitted. Returns
// nil when the whole fleet scanned cleanly.
func (r *Report) DegradedByCluster() map[string]int {
	if len(r.Degraded) == 0 {
		return nil
	}
	out := make(map[string]int, len(r.Degraded))
	for _, d := range r.Degraded {
		out[d.Cluster]++
	}
	return out
}

// sortScannerStatuses orders degraded-coverage entries by cluster then scanner
// so report output is stable across runs.
func sortScannerStatuses(s []ScannerStatus) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].Cluster != s[j].Cluster {
			return s[i].Cluster < s[j].Cluster
		}
		return s[i].Scanner < s[j].Scanner
	})
}

// buildCategories creates category groupings for the scanned scanner names.
func buildCategories(scanned []string) []Category {
	scannedSet := make(map[string]struct{}, len(scanned))
	for _, s := range scanned {
		scannedSet[s] = struct{}{}
	}

	var categories []Category
	for _, cat := range Categories() {
		var present []string
		for _, s := range cat.Scanners {
			if _, ok := scannedSet[s]; ok {
				present = append(present, s)
			}
		}
		if len(present) > 0 {
			categories = append(categories, Category{
				Name:     cat.Name,
				Scanners: present,
			})
		}
	}
	return categories
}

// buildSummary computes the fleet-wide section statistics. The finding counts are set by
// countFindings once the findings exist.
func buildSummary(clusters []string, sections map[string]*SectionReport) Summary {
	s := Summary{
		ClusterCount: len(clusters),
		ScannerCount: len(sections),
	}
	for _, sec := range sections {
		if sec.Uniform {
			s.UniformCount++
		} else {
			s.DivergentCount++
		}
		s.TotalDivergences += len(sec.Divergences)
	}
	return s
}

// countFindings sets s's critical and warning counts from findings, so the summary states the
// same numbers as the findings list.
func countFindings(s *Summary, findings []Finding) {
	s.CriticalCount, s.WarningCount = 0, 0
	for _, f := range findings {
		switch f.Severity {
		case SeverityCritical:
			s.CriticalCount++
		case SeverityWarning:
			s.WarningCount++
		}
	}
}

// GroupFindingsByCluster buckets findings by cluster, using "fleet" as the key for
// cross-cluster findings.
func GroupFindingsByCluster(findings []Finding) map[string][]Finding {
	out := map[string][]Finding{}
	for _, f := range findings {
		key := f.Cluster
		if key == "" {
			key = "fleet"
		}
		out[key] = append(out[key], f)
	}
	return out
}
