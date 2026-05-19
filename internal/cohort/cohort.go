// Package cohort partitions a fleet into groups of clusters that look like
// each other. User-supplied tags win when present. Without tags, agglomerative
// clustering on a feature vector groups similar clusters so that drift
// detection can run within cohort instead of across the entire fleet.
package cohort

import (
	"fmt"
	"sort"
)

// Source indicates how a cohort was determined.
type Source string

const (
	// SourceTagged means the cohort came from a user-supplied cluster tag.
	SourceTagged Source = "tagged"
	// SourceAuto means the cohort was derived by clustering scanner data.
	SourceAuto Source = "auto"
	// SourceFleet means the fleet was too small or too uniform to subdivide.
	SourceFleet Source = "fleet"
)

// DefaultTagKey is the cluster-tag key that carries a cohort label.
const DefaultTagKey = "cohort"

// Defaults that callers normally accept without thinking.
const (
	// defaultMinClusters is the fleet size below which auto-cohorting is
	// skipped. Below this we cannot pick a meaningful K from silhouette
	// or merge-gap heuristics, and statistical detection wants every
	// cluster anyway.
	defaultMinClusters = 6
	// defaultMinCohortSize is the smallest cohort the algorithm will leave
	// standing. Smaller buckets get folded back into the closest cohort.
	defaultMinCohortSize = 3
	// defaultMaxCohorts caps the result. Drift-attribution graphs become
	// noisy beyond about eight buckets.
	defaultMaxCohorts = 8
)

// Cohort is a group of clusters that look similar enough to share a baseline.
type Cohort struct {
	// Name is the cohort label. For tagged cohorts this is the tag value.
	// For auto-detected cohorts this is "auto-N" with a stable index.
	Name string `json:"name"`
	// Source identifies how this cohort was produced.
	Source Source `json:"source"`
	// Clusters lists the member cluster names, sorted for stable output.
	Clusters []string `json:"clusters"`
}

// ClusterProfile is the per-cluster input to Assign. Features must be aligned
// across profiles, in the same order, and already normalized to roughly [0,1].
// Tag is the user-supplied cohort label or "" if none was set.
type ClusterProfile struct {
	// Name is the cluster name.
	Name string
	// Features is the normalized feature vector. All profiles share the
	// same feature order.
	Features []float64
	// Tag is the user-supplied cohort label, "" when unset.
	Tag string
}

// Options controls cohort assignment.
type Options struct {
	// MinClusters is the fleet size below which auto-cohorting is skipped.
	// Zero means use the package default.
	MinClusters int
	// MinCohortSize is the smallest cohort the algorithm will keep.
	// Cohorts below this size are folded into their nearest neighbor.
	// Zero means use the package default.
	MinCohortSize int
	// MaxCohorts caps the number of auto-detected cohorts.
	// Zero means use the package default.
	MaxCohorts int
}

// Assign partitions clusters into cohorts. Profiles carrying a non-empty Tag
// land in tagged cohorts named after the tag. Untagged profiles get
// auto-assigned via average-linkage agglomerative clustering on their feature
// vectors, with K chosen from the largest gap in the merge sequence. When the
// fleet is too small to subdivide, every cluster lands in a single "fleet"
// cohort.
func Assign(profiles []ClusterProfile, opts Options) []Cohort {
	if opts.MinClusters == 0 {
		opts.MinClusters = defaultMinClusters
	}
	if opts.MinCohortSize == 0 {
		opts.MinCohortSize = defaultMinCohortSize
	}
	if opts.MaxCohorts == 0 {
		opts.MaxCohorts = defaultMaxCohorts
	}

	tagged, untagged := splitByTag(profiles)
	cohorts := taggedCohorts(tagged)

	if len(untagged) == 0 {
		return finalize(cohorts)
	}

	if len(untagged) < opts.MinClusters {
		cohorts = append(cohorts, Cohort{
			Name:     "fleet",
			Source:   SourceFleet,
			Clusters: profileNames(untagged),
		})
		return finalize(cohorts)
	}

	auto := autoCohorts(untagged, opts)
	cohorts = append(cohorts, auto...)
	return finalize(cohorts)
}

// splitByTag separates profiles by whether they carry a cohort tag.
func splitByTag(profiles []ClusterProfile) (tagged, untagged []ClusterProfile) {
	for _, p := range profiles {
		if p.Tag != "" {
			tagged = append(tagged, p)
			continue
		}
		untagged = append(untagged, p)
	}
	return tagged, untagged
}

// taggedCohorts groups tagged profiles by tag value.
func taggedCohorts(profiles []ClusterProfile) []Cohort {
	byTag := make(map[string][]string)
	for _, p := range profiles {
		byTag[p.Tag] = append(byTag[p.Tag], p.Name)
	}
	out := make([]Cohort, 0, len(byTag))
	for tag, members := range byTag {
		out = append(out, Cohort{
			Name:     tag,
			Source:   SourceTagged,
			Clusters: members,
		})
	}
	return out
}

// autoCohorts runs agglomerative clustering on untagged profiles. The result
// is named "auto-1", "auto-2", and so on, with indices assigned in order of
// the cohorts' alphabetically-first member for stable output.
func autoCohorts(profiles []ClusterProfile, opts Options) []Cohort {
	groups := agglomerate(profiles, opts.MaxCohorts)
	groups = mergeSmallCohorts(groups, profiles, opts.MinCohortSize)
	return nameAutoCohorts(groups, profiles)
}

// nameAutoCohorts converts index-based group assignments into stable Cohort
// values. Cohorts are sorted by their first member's name so repeated runs on
// the same data produce identical output.
func nameAutoCohorts(groups []int, profiles []ClusterProfile) []Cohort {
	byGroup := make(map[int][]string)
	for i, g := range groups {
		byGroup[g] = append(byGroup[g], profiles[i].Name)
	}
	for _, members := range byGroup {
		sort.Strings(members)
	}
	type bucket struct {
		members []string
		first   string
	}
	buckets := make([]bucket, 0, len(byGroup))
	for _, members := range byGroup {
		buckets = append(buckets, bucket{members: members, first: members[0]})
	}
	sort.Slice(buckets, func(i, j int) bool { return buckets[i].first < buckets[j].first })
	out := make([]Cohort, 0, len(buckets))
	for i, b := range buckets {
		out = append(out, Cohort{
			Name:     fmt.Sprintf("auto-%d", i+1),
			Source:   SourceAuto,
			Clusters: b.members,
		})
	}
	return out
}

// profileNames returns the names of profiles in input order.
func profileNames(profiles []ClusterProfile) []string {
	out := make([]string, len(profiles))
	for i, p := range profiles {
		out[i] = p.Name
	}
	return out
}

// finalize sorts each cohort's member list and the cohort slice itself so the
// output is stable across runs.
func finalize(cohorts []Cohort) []Cohort {
	for i := range cohorts {
		sort.Strings(cohorts[i].Clusters)
	}
	sort.Slice(cohorts, func(i, j int) bool {
		if cohorts[i].Source != cohorts[j].Source {
			return cohorts[i].Source < cohorts[j].Source
		}
		return cohorts[i].Name < cohorts[j].Name
	})
	return cohorts
}
