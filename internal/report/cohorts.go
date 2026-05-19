package report

import (
	"github.com/dcadolph/fleetsweeper/internal/cohort"
)

// CohortSummary describes one cohort in the report: its name, how it was
// derived, the clusters it contains, and the outliers that show up against
// the cohort's own baseline rather than the fleet's. The cohort view picks
// up drift the fleet-level view drowns out, because edge and prod clusters
// have different "normal" without being wrong.
type CohortSummary struct {
	// Name is the cohort label (tag value for tagged cohorts, "auto-N" for
	// auto-detected cohorts, or "fleet" for too-small fleets).
	Name string `json:"name"`
	// Source identifies how the cohort was produced.
	Source string `json:"source"`
	// Clusters lists the member cluster names, sorted.
	Clusters []string `json:"clusters"`
	// Outliers are clusters that deviate from this cohort's baseline.
	Outliers []OutlierResult `json:"outliers,omitempty"`
}

// cohortSectionLookup adapts the report's section map to cohort.SectionLookup.
type cohortSectionLookup struct {
	sections map[string]*SectionReport
}

// PerCluster returns the per-cluster scanner data for a single scanner.
func (l cohortSectionLookup) PerCluster(name string) map[string]any {
	sec, ok := l.sections[name]
	if !ok {
		return nil
	}
	return sec.PerCluster
}

// buildCohorts assigns clusters to cohorts and runs MAD-based outlier
// detection within each cohort that is large enough to be statistically
// meaningful. Cohorts below minMADSample participants contribute their
// members and source but no outliers.
func buildCohorts(r *Report, tags map[string]string, threshold float64) []CohortSummary {
	if len(r.Clusters) == 0 {
		return nil
	}
	profiles := cohort.Profiles(r.Clusters, cohortSectionLookup{sections: r.Sections}, tags)
	groups := cohort.Assign(profiles, cohort.Options{})

	out := make([]CohortSummary, 0, len(groups))
	for _, g := range groups {
		summary := CohortSummary{
			Name:     g.Name,
			Source:   string(g.Source),
			Clusters: g.Clusters,
		}
		if len(g.Clusters) >= minMADSample {
			summary.Outliers = detectCohortOutliers(r, g.Clusters, threshold)
		}
		out = append(out, summary)
	}
	return out
}

// detectCohortOutliers runs the same MAD-based numeric/string/set detection
// the fleet view uses, but scoped to the given cluster subset. The returned
// outliers compare each cluster against the cohort's own median or mode,
// which is what surfaces drift that is invisible at fleet scale.
func detectCohortOutliers(r *Report, members []string, threshold float64) []OutlierResult {
	subReport := &Report{
		Clusters: members,
		Sections: r.Sections,
	}
	return DetectOutliers(subReport, threshold)
}
