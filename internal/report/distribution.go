package report

import (
	"math"
	"sort"
)

// maxMassZ caps how much one value adds to a distribution's Mass and a
// cluster's deviation mass, so a single runaway field cannot drown out every
// other one.
const maxMassZ = 10.0

// Distribution is the population a fleet-relative detector measured one field
// against: every cluster's value, the norm, and which clusters it flagged. It
// is the data behind the strip and matrix views, and its norm is the one each
// finding's NormBasis quotes.
type Distribution struct {
	// Scope is "fleet" or the name of the cohort the population was drawn from.
	Scope string `json:"scope"`
	// Scanner is the scanner that reported the field.
	Scanner string `json:"scanner"`
	// Field is the field within the scanner's data.
	Field string `json:"field"`
	// Kind is "numeric", "string", or "set".
	Kind string `json:"kind"`
	// Values holds one entry per cluster in the population, in report cluster
	// order.
	Values []ClusterValue `json:"values"`
	// Median is the population median of a numeric field.
	Median float64 `json:"median"`
	// MAD is the median absolute deviation of a numeric field from Median.
	MAD float64 `json:"mad"`
	// Band is how far from Median a numeric value may sit before it is
	// flagged: Threshold * MAD / 0.6745. Zero when MAD is zero.
	Band float64 `json:"band"`
	// Threshold is the cutoff the detector applied: the modified z-score for
	// numeric, the minimum mode share for string, and the minimum presence
	// share for set membership.
	Threshold float64 `json:"threshold"`
	// Mode is the most common value of a string field.
	Mode string `json:"mode,omitempty"`
	// ModeShare is the fraction of the population holding Mode.
	ModeShare float64 `json:"mode_share,omitempty"`
	// Consensus lists the members of a set field present in at least
	// Threshold of the population, sorted.
	Consensus []string `json:"consensus,omitempty"`
	// SampleSize is the number of clusters in the population.
	SampleSize int `json:"sample_size"`
	// LimitedSample marks a population too small for MAD, judged by the
	// leave-one-out majority diff.
	LimitedSample bool `json:"limited_sample,omitempty"`
	// Mass is the sum over Values of |Z| capped at 10.
	Mass float64 `json:"mass"`
}

// ClusterValue is one cluster's value in a Distribution. Which value fields
// apply depends on the distribution's Kind.
type ClusterValue struct {
	// Cluster is the cluster name.
	Cluster string `json:"cluster"`
	// Number is the value of a numeric field.
	Number *float64 `json:"number,omitempty"`
	// Text is the value of a string field.
	Text string `json:"text,omitempty"`
	// Size is how many members a set field has on this cluster.
	Size int `json:"size,omitempty"`
	// Missing lists the consensus members a set field lacks on this cluster,
	// sorted. Every other consensus member is present.
	Missing []string `json:"missing,omitempty"`
	// Z is the signed modified z-score of a numeric value, zero when MAD is
	// zero. In a limited sample a flagged cluster's Z is measured against the
	// other clusters, as its finding quotes.
	Z float64 `json:"z,omitempty"`
	// Outlier is true when the detector flagged this cluster.
	Outlier bool `json:"outlier,omitempty"`
	// Explained names the operator-tagged cohort whose own norm holds this
	// fleet outlier, empty otherwise. An explained outlier raises no finding.
	Explained string `json:"explained,omitempty"`
}

// massOf returns the sum over values of |Z| capped at maxMassZ.
func massOf(values []ClusterValue) float64 {
	var mass float64
	for _, v := range values {
		mass += math.Min(math.Abs(v.Z), maxMassZ)
	}
	return mass
}

// markOutliers sets Outlier, and Z when z is true, on the values of d whose
// cluster has a result in outliers.
func markOutliers(d *Distribution, outliers []OutlierResult, z bool) {
	byCluster := make(map[string]OutlierResult, len(outliers))
	for _, o := range outliers {
		byCluster[o.Cluster] = o
	}
	for i := range d.Values {
		o, ok := byCluster[d.Values[i].Cluster]
		if !ok {
			continue
		}
		d.Values[i].Outlier = true
		if z {
			d.Values[i].Z = o.Z
		}
	}
}

// deviationMass sums, per cluster, the capped |z| of its values across the
// fleet-scope distributions, each z taken by normZ. Clusters with zero mass are
// left out, and a nil map means no cluster deviates at all.
func deviationMass(dists []Distribution, normZ func(d Distribution, v ClusterValue) float64) map[string]float64 {
	var out map[string]float64
	for _, d := range dists {
		if d.Scope != NormScopeFleet {
			continue
		}
		for _, v := range d.Values {
			m := math.Min(math.Abs(normZ(d, v)), maxMassZ)
			if m == 0 {
				continue
			}
			if out == nil {
				out = make(map[string]float64)
			}
			out[v.Cluster] += m
		}
	}
	return out
}

// sortDistributions orders distributions fleet first and then by cohort name,
// and within a scope by descending mass, then scanner and field, so report
// output is stable and the most deviant fields come first.
func sortDistributions(dists []Distribution) {
	sort.SliceStable(dists, func(i, j int) bool {
		a, b := dists[i], dists[j]
		if (a.Scope == NormScopeFleet) != (b.Scope == NormScopeFleet) {
			return a.Scope == NormScopeFleet
		}
		if a.Scope != b.Scope {
			return a.Scope < b.Scope
		}
		if a.Mass != b.Mass {
			return a.Mass > b.Mass
		}
		if a.Scanner != b.Scanner {
			return a.Scanner < b.Scanner
		}
		return a.Field < b.Field
	})
}
