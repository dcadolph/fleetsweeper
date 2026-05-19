package report

import (
	"fmt"
	"sort"

	"github.com/dcadolph/fleetsweeper/internal/cohort"
)

// minMisCohortFleet is the fleet size below which mis-cohort detection is
// skipped. Below this the auto-cohort assignment is too noisy for
// disagreement with a tag to mean anything.
const minMisCohortFleet = 8

// minTagPopulation is the minimum number of clusters that must share a tag
// before that tag is treated as having a "majority" auto-cohort. Two clusters
// is not enough to know which one is mis-tagged.
const minTagPopulation = 3

// MisCohortFinding describes a cluster whose user-applied cohort tag does not
// match where its scanner profile places it. This catches mislabeled clusters
// that survived because every existing tool only looks at one cluster at a
// time.
type MisCohortFinding struct {
	// Cluster is the cluster whose tag disagrees with its profile.
	Cluster string `json:"cluster"`
	// TaggedAs is the user-applied cohort tag the cluster carries.
	TaggedAs string `json:"tagged_as"`
	// ProfileMatches is the cohort tag a majority of similar clusters carry.
	ProfileMatches string `json:"profile_matches"`
}

// detectMisCohort flags clusters whose user-supplied cohort tag disagrees
// with the auto-cohort assignment derived from their scanner profile. The
// algorithm:
//  1. Build feature vectors for every cluster.
//  2. Run agglomerative clustering with tags hidden, so the auto-cohort is
//     purely profile-driven.
//  3. For each tag, find the auto-cohort that holds the most members of that
//     tag (the tag's "true home").
//  4. Any tagged cluster sitting in a different auto-cohort is flagged.
func detectMisCohort(r *Report, tags map[string]string) []MisCohortFinding {
	if len(r.Clusters) < minMisCohortFleet || len(tags) == 0 {
		return nil
	}
	// Strip tags so the auto-cohort assignment is profile-only.
	profiles := cohort.Profiles(r.Clusters, cohortSectionLookup{sections: r.Sections}, nil)
	autoCohorts := cohort.Assign(profiles, cohort.Options{})

	// Map cluster -> auto-cohort name.
	clusterAuto := make(map[string]string, len(r.Clusters))
	for _, c := range autoCohorts {
		for _, cl := range c.Clusters {
			clusterAuto[cl] = c.Name
		}
	}

	// For each tag, find the auto-cohort that holds the most members.
	tagPop := make(map[string]int)
	for _, t := range tags {
		if t != "" {
			tagPop[t]++
		}
	}
	dominantAuto := make(map[string]string)
	for tag, pop := range tagPop {
		if pop < minTagPopulation {
			continue
		}
		counts := make(map[string]int)
		for cluster, ctag := range tags {
			if ctag != tag {
				continue
			}
			counts[clusterAuto[cluster]]++
		}
		dominantAuto[tag] = argmax(counts)
	}

	// Flag any tagged cluster whose auto-cohort is not the dominant one
	// for its tag.
	var findings []MisCohortFinding
	for cluster, tag := range tags {
		if tag == "" {
			continue
		}
		dom, ok := dominantAuto[tag]
		if !ok {
			continue
		}
		mine := clusterAuto[cluster]
		if mine == "" || mine == dom {
			continue
		}
		// Find the tag whose dominant auto-cohort matches this cluster's
		// actual auto-cohort. That is the tag the profile suggests.
		var matches string
		for otherTag, otherDom := range dominantAuto {
			if otherTag == tag {
				continue
			}
			if otherDom == mine {
				matches = otherTag
				break
			}
		}
		findings = append(findings, MisCohortFinding{
			Cluster:        cluster,
			TaggedAs:       tag,
			ProfileMatches: matches,
		})
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Cluster < findings[j].Cluster })
	return findings
}

// argmax returns the key with the largest value. Ties break by lexicographic
// order on the key so output is stable.
func argmax(counts map[string]int) string {
	var best string
	bestN := -1
	for k, v := range counts {
		if v > bestN || (v == bestN && k < best) {
			best = k
			bestN = v
		}
	}
	return best
}

// misCohortFindings converts mis-cohort detection into the standard Finding
// shape so they surface alongside everything else in the report and in the
// UI's findings panel.
func misCohortFindings(r *Report, tags map[string]string) []Finding {
	raw := detectMisCohort(r, tags)
	out := make([]Finding, 0, len(raw))
	for _, m := range raw {
		desc := fmt.Sprintf(
			"Cluster %q is tagged %s=%q, but its scanner profile clusters with the %q population.",
			m.Cluster, cohort.DefaultTagKey, m.TaggedAs, m.ProfileMatches,
		)
		if m.ProfileMatches == "" {
			desc = fmt.Sprintf(
				"Cluster %q is tagged %s=%q, but its scanner profile does not match the rest of the %q cohort.",
				m.Cluster, cohort.DefaultTagKey, m.TaggedAs, m.TaggedAs,
			)
		}
		out = append(out, Finding{
			Title:       "Cluster may be in the wrong cohort",
			Description: desc,
			Severity:    SeverityWarning,
			Cluster:     m.Cluster,
			Scanner:     "cohort",
			Affected:    []string{m.Cluster},
		})
	}
	return out
}
