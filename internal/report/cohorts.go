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
	// sections maps scanner name to its section report.
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

// buildCohorts assigns clusters to cohorts and runs outlier detection within
// each one: MAD for cohorts of minMADSample clusters or more, the
// leave-one-out majority diff for cohorts of minMajoritySample to
// minMADSample-1. Smaller cohorts contribute their members and source but no
// outliers. It also returns the distribution behind every field each cohort
// evaluated.
func buildCohorts(r *Report, tags map[string]string, threshold float64) ([]CohortSummary, []Distribution) {
	if len(r.Clusters) == 0 {
		return nil, nil
	}
	profiles := cohort.Profiles(r.Clusters, cohortSectionLookup{sections: r.Sections}, tags)
	groups := cohort.Assign(profiles, cohort.Options{})

	out := make([]CohortSummary, 0, len(groups))
	var dists []Distribution
	for _, g := range groups {
		summary := CohortSummary{
			Name:     g.Name,
			Source:   string(g.Source),
			Clusters: g.Clusters,
		}
		var found []Distribution
		switch {
		case len(g.Clusters) >= minMADSample:
			summary.Outliers, found = detectOutliers(r, g.Clusters, threshold, g.Name)
		case len(g.Clusters) >= minMajoritySample:
			summary.Outliers, found = detectMajorityOutliers(r, g.Clusters, threshold, g.Name)
		}
		dists = append(dists, found...)
		out = append(out, summary)
	}
	return out, dists
}

// cohortMapPeers is how many nearest peers the cohort map lists per cluster.
const cohortMapPeers = 5

// CohortMapFor lays the fleet of r out on a cohort map, from the same feature
// vectors cohort assignment uses, with r's cohorts as the groups and five
// nearest peers per cluster. It is computed on demand rather than in Build
// because classical scaling is cubic in the fleet size.
func CohortMapFor(r *Report) cohort.Map {
	if r == nil || len(r.Clusters) == 0 {
		return cohort.Map{}
	}
	profiles := cohort.Profiles(r.Clusters, cohortSectionLookup{sections: r.Sections}, nil)
	groups := make([]cohort.Cohort, 0, len(r.Cohorts))
	for _, c := range r.Cohorts {
		groups = append(groups, cohort.Cohort{Name: c.Name, Source: cohort.Source(c.Source), Clusters: c.Clusters})
	}
	return cohort.BuildMap(profiles, groups, cohortMapPeers)
}
