package report

import (
	"fmt"
	"math"
	"slices"

	"github.com/dcadolph/fleetsweeper/internal/cohort"
)

// applyCohortNorms measures each cluster in an operator-tagged cohort against
// its cohort's norm, the population the operator declared it belongs to, and
// every other cluster against the fleet. A tagged cluster's fleet outlier that
// its cohort holds within the cohort's norm is marked explained: production
// clusters are larger than edge clusters by design, so that is not drift. The
// outlier stays in the report and the fleet distribution, marked with the
// cohort, and raises no finding. Deviation mass, per cluster and per fleet
// distribution, takes a tagged cluster's z from its cohort's distribution of
// the field where there is one. A cluster in an auto-derived cohort, or in a
// cohort with no norm for the field, keeps its fleet finding and fleet z. A
// tagged cohort of two has no norm of its own, so holdTaggedPairs decides it.
func applyCohortNorms(r *Report, cohortDists []Distribution) {
	tagged := map[string]string{}
	for _, c := range r.Cohorts {
		if c.Source != string(cohort.SourceTagged) {
			continue
		}
		for _, cl := range c.Clusters {
			tagged[cl] = c.Name
		}
	}
	type key struct{ scope, scanner, field, cluster string }
	inNorm := map[key]bool{}
	cohortZ := map[key]float64{}
	for _, d := range cohortDists {
		for _, v := range d.Values {
			k := key{d.Scope, d.Scanner, d.Field, v.Cluster}
			inNorm[k], cohortZ[k] = withinNorm(d, v), valueMass(d, v)
		}
	}
	explained := map[key]string{}
	for i, o := range r.Outliers {
		c, ok := tagged[o.Cluster]
		if !ok || !inNorm[key{c, o.Scanner, o.Field, o.Cluster}] {
			continue
		}
		r.Outliers[i].ExplainedBy = c
		explained[key{NormScopeFleet, o.Scanner, o.Field, o.Cluster}] = c
	}
	for i, c := range holdTaggedPairs(r, cohortDists) {
		r.Outliers[i].ExplainedBy = c
		o := r.Outliers[i]
		explained[key{NormScopeFleet, o.Scanner, o.Field, o.Cluster}] = c
	}
	normZ := func(d Distribution, v ClusterValue) float64 {
		if c, ok := tagged[v.Cluster]; ok {
			if z, ok := cohortZ[key{c, d.Scanner, d.Field, v.Cluster}]; ok {
				return z
			}
		}
		return valueMass(d, v)
	}
	for di := range r.Distributions {
		d := &r.Distributions[di]
		if d.Scope != NormScopeFleet {
			continue
		}
		var mass float64
		for vi := range d.Values {
			if c, ok := explained[key{NormScopeFleet, d.Scanner, d.Field, d.Values[vi].Cluster}]; ok {
				d.Values[vi].Explained = c
			}
			mass += normZ(*d, d.Values[vi])
		}
		d.Mass = mass
	}
	r.DeviationMass = deviationMass(r.Distributions, normZ)
}

// holdTaggedPairs returns, by index into r.Outliers, the fleet outliers a tagged cohort of two
// members holds, mapped to the cohort's name. Two members are too few for a cohort norm, so the
// pair holds an outlier when both members are fleet outliers on the same scanner and field and
// agree: the same side of the norm for a numeric field (the same value for an exact norm), the
// same text for a string field, and the same missing members for a set field. A tagged cohort
// of one holds nothing, and r.Notes says so once per cohort.
func holdTaggedPairs(r *Report, cohortDists []Distribution) map[int]string {
	normed := map[string]bool{}
	for _, d := range cohortDists {
		normed[d.Scope] = true
	}
	type pair struct{ other, cohort string }
	partner := map[string]pair{}
	for _, c := range r.Cohorts {
		if c.Source != string(cohort.SourceTagged) || normed[c.Name] {
			continue
		}
		switch len(c.Clusters) {
		case 1:
			r.Notes = append(r.Notes, fmt.Sprintf(
				"Cohort %s has one cluster, so it holds no outlier.", c.Name))
		case 2:
			a, b := c.Clusters[0], c.Clusters[1]
			partner[a], partner[b] = pair{b, c.Name}, pair{a, c.Name}
		}
	}
	if len(partner) == 0 {
		return nil
	}
	type key struct{ scanner, field, cluster string }
	fleet := map[key]int{}
	for i, o := range r.Outliers {
		if o.Scope == NormScopeFleet {
			fleet[key{o.Scanner, o.Field, o.Cluster}] = i
		}
	}
	held := map[int]string{}
	for i, o := range r.Outliers {
		p, ok := partner[o.Cluster]
		if !ok || o.Scope != NormScopeFleet {
			continue
		}
		if j, ok := fleet[key{o.Scanner, o.Field, p.other}]; ok && pairAgrees(o, r.Outliers[j]) {
			held[i] = p.cohort
		}
	}
	return held
}

// pairAgrees reports whether two fleet outliers on one field deviate the same way.
func pairAgrees(a, b OutlierResult) bool {
	switch a.Kind {
	case NormKindNumeric:
		if a.Exact || b.Exact {
			return a.Exact && b.Exact && a.Value == b.Value
		}
		return math.Signbit(a.Z) == math.Signbit(b.Z) && a.Z != 0 && b.Z != 0
	case NormKindSet:
		return slices.Equal(a.Missing, b.Missing)
	default:
		return a.Value == b.Value
	}
}

// withinNorm reports whether v sits inside the norm of d: within the band of
// a numeric field, or at the median when the spread is zero; on the mode of a
// string field; holding every consensus member of a set field. The detector's
// own flag is not enough, since a small cohort flags at most one cluster per
// field.
func withinNorm(d Distribution, v ClusterValue) bool {
	switch d.Kind {
	case NormKindNumeric:
		if v.Number == nil {
			return false
		}
		if d.MAD == 0 {
			return *v.Number == d.Median
		}
		return math.Abs(*v.Number-d.Median) <= d.Band
	case NormKindSet:
		return !v.Outlier && len(v.Missing) == 0
	default:
		return d.Mode != "" && v.Text == d.Mode
	}
}
