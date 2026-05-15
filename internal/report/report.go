package report

import (
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
		{Name: "Cluster Info", Scanners: []string{"version", "namespaces", "crds"}},
		{Name: "Workloads", Scanners: []string{"services", "ingresses"}},
		{Name: "Health & Resources", Scanners: []string{"node-health", "metrics", "resources", "resource-quotas"}},
		{Name: "Security & Access", Scanners: []string{"rbac", "security", "network-policies"}},
		{Name: "Events & Logs", Scanners: []string{"events"}},
	}
}

// Report is the top-level output structure.
type Report struct {
	// Timestamp is when the scan was executed.
	Timestamp string `json:"timestamp"`
	// Clusters lists the kubeconfig contexts that were scanned.
	Clusters []string `json:"clusters"`
	// Categories groups sections by functional area.
	Categories []CategoryReport `json:"categories"`
	// Sections holds per-scanner comparison results keyed by scanner name.
	Sections map[string]*SectionReport `json:"sections"`
	// Summary holds fleet-wide summary statistics.
	Summary Summary `json:"summary"`
	// Findings lists human-readable issues discovered across the fleet.
	Findings []Finding `json:"findings"`
	// ClusterHealths holds per-cluster health summaries.
	ClusterHealths []ClusterHealth `json:"cluster_healths"`
}

// CategoryReport holds a category and its scanner names for the report.
type CategoryReport struct {
	// Name is the category display name.
	Name string `json:"name"`
	// Scanners lists scanner names in this category.
	Scanners []string `json:"scanners"`
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
	// CriticalCount is the number of critical-severity divergences.
	CriticalCount int `json:"critical_count"`
	// WarningCount is the number of warning-severity divergences.
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
	// Severity indicates how important this divergence is.
	Severity string `json:"severity"`
	// Values maps cluster name to the value it reported for this field.
	Values map[string]string `json:"values"`
}

// Build creates a Report from per-cluster scanner results. The results map is
// keyed by cluster name, then by scanner name.
func Build(clusters []string, results map[string]map[string]scanner.Result) *Report {
	r := &Report{
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Clusters:  clusters,
		Sections:  make(map[string]*SectionReport),
	}

	scannerNames := collectScannerNames(results)
	for _, name := range scannerNames {
		perCluster := make(map[string]any, len(clusters))
		for _, cluster := range clusters {
			if res, ok := results[cluster][name]; ok {
				perCluster[cluster] = res.Data
			}
		}
		section := compare(clusters, perCluster)
		applySeverity(name, section)
		r.Sections[name] = section
	}

	r.Categories = buildCategories(scannerNames)
	r.Summary = buildSummary(clusters, r.Sections)
	r.Findings = GenerateFindings(r)
	r.ClusterHealths = GenerateClusterHealth(r, r.Findings)

	return r
}

// buildCategories creates category groupings for the scanned scanner names.
func buildCategories(scanned []string) []CategoryReport {
	scannedSet := make(map[string]struct{}, len(scanned))
	for _, s := range scanned {
		scannedSet[s] = struct{}{}
	}

	var categories []CategoryReport
	for _, cat := range Categories() {
		var present []string
		for _, s := range cat.Scanners {
			if _, ok := scannedSet[s]; ok {
				present = append(present, s)
			}
		}
		if len(present) > 0 {
			categories = append(categories, CategoryReport{
				Name:     cat.Name,
				Scanners: present,
			})
		}
	}
	return categories
}

// buildSummary computes fleet-wide statistics from section reports.
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
		for _, d := range sec.Divergences {
			s.TotalDivergences++
			switch d.Severity {
			case SeverityCritical:
				s.CriticalCount++
			case SeverityWarning:
				s.WarningCount++
			}
		}
	}
	return s
}

// collectScannerNames gathers unique scanner names across all clusters in sorted order.
func collectScannerNames(results map[string]map[string]scanner.Result) []string {
	seen := make(map[string]struct{})
	for _, scanners := range results {
		for name := range scanners {
			seen[name] = struct{}{}
		}
	}
	names := make([]string, 0, len(seen))
	for name := range seen {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
