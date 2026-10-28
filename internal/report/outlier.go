package report

import (
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"sort"
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/util"
)

// minMADSample is the minimum number of values required before MAD-based
// outlier detection emits any finding. Below this the median itself is
// unreliable and false positives dominate.
const minMADSample = 8

// minStringModeMass is the minimum share of the population the mode must hold
// before string outliers are flagged. Without this guard a three-way tied
// version distribution incorrectly flagged 2/3 of the fleet as outliers.
const minStringModeMass = 0.6

// maxReportedDeviation is the finite stand-in cappedZ uses for an infinite z-score, so a
// score from a MAD negligibly small next to the spread stays JSON-safe. A MAD of exactly zero
// never reaches it: such a field is judged by exactOutliers instead.
const maxReportedDeviation = 1e6

// minSetConsensusShare is the share of the population an item must appear in
// before a set field treats it as part of the consensus.
const minSetConsensusShare = 0.6

// madScale converts a MAD into a standard-deviation-equivalent scale, so the
// modified z-score of a normal population matches its ordinary z-score.
const madScale = 0.6745

// Norm kinds name the detector that measured a fleet-relative field.
const (
	NormKindNumeric = "numeric"
	NormKindString  = "string"
	NormKindSet     = "set"
)

// NormScopeFleet is the scope of a norm computed over the whole fleet. A
// cohort norm carries the cohort name instead.
const NormScopeFleet = "fleet"

// NormBasis states the norm a fleet-relative finding was measured against, so
// a reader can check the claim without rerunning the statistics. Which fields
// apply depends on Kind. Absolute-rule findings carry no NormBasis.
type NormBasis struct {
	// Scope is "fleet" or the name of the cohort the norm was computed over.
	Scope string `json:"scope"`
	// Field is the scanner field the norm describes.
	Field string `json:"field"`
	// Kind is "numeric", "string", or "set".
	Kind string `json:"kind"`
	// Median is the population median of a numeric field.
	Median float64 `json:"median"`
	// MAD is the median absolute deviation of a numeric field from Median.
	MAD float64 `json:"mad"`
	// Mode is the most common value of a string field.
	Mode string `json:"mode,omitempty"`
	// ModeShare is the fraction of the population holding Mode, or holding Median for an exact
	// numeric norm.
	ModeShare float64 `json:"mode_share,omitempty"`
	// Consensus lists the members of a set field present in at least
	// Threshold of the population, sorted.
	Consensus []string `json:"consensus,omitempty"`
	// Missing lists the consensus members this cluster lacks, sorted.
	Missing []string `json:"missing,omitempty"`
	// SampleSize is the number of clusters in the population.
	SampleSize int `json:"sample_size"`
	// Threshold is the cutoff the detector applied: the modified z-score for
	// numeric, the minimum mode share for string, and the minimum presence
	// share for set membership.
	Threshold float64 `json:"threshold"`
	// Value is this cluster's value for the field.
	Value string `json:"value"`
	// Z is this cluster's signed modified z-score for a numeric field.
	Z float64 `json:"z"`
	// LimitedSample marks a norm drawn from a population too small for MAD.
	LimitedSample bool `json:"limited_sample"`
	// Exact marks a numeric norm with zero spread, judged like a string: at least
	// minStringModeMass of the population holds Median exactly and any other value is off it.
	// An exact norm carries no z-score and no band.
	Exact bool `json:"exact,omitempty"`
	// NoWhatIf explains why no what-if can project a fix toward this norm.
	// Empty when one can.
	NoWhatIf string `json:"no_what_if,omitempty"`
}

// OutlierResult describes a cluster that deviates from the fleet norm.
type OutlierResult struct {
	// Cluster is the cluster that deviates.
	Cluster string `json:"cluster"`
	// Field is the data field that deviates.
	Field string `json:"field"`
	// Value is the cluster's value for the field.
	Value string `json:"value"`
	// FleetNorm is the typical fleet value (median for numeric, mode for string).
	FleetNorm string `json:"fleet_norm"`
	// Deviation is the modified z-score for numeric fields.
	Deviation float64 `json:"deviation,omitempty"`
	// Scanner is the scanner that produced this data.
	Scanner string `json:"scanner"`
	// Severity is critical, warning, or info.
	Severity string `json:"severity"`
	// Scope is "fleet" or the name of the cohort the norm was computed over.
	Scope string `json:"scope"`
	// Kind is "numeric", "string", or "set".
	Kind string `json:"kind"`
	// Median is the population median of a numeric field.
	Median float64 `json:"median"`
	// MAD is the median absolute deviation of a numeric field from Median.
	MAD float64 `json:"mad"`
	// Mode is the most common value of a string field.
	Mode string `json:"mode,omitempty"`
	// ModeShare is the fraction of the population holding Mode.
	ModeShare float64 `json:"mode_share,omitempty"`
	// Consensus lists the consensus members of a set field, sorted.
	Consensus []string `json:"consensus,omitempty"`
	// Missing lists the consensus members this cluster lacks, sorted.
	Missing []string `json:"missing,omitempty"`
	// SampleSize is the number of clusters in the population.
	SampleSize int `json:"sample_size"`
	// Threshold is the cutoff the detector applied (see NormBasis.Threshold).
	Threshold float64 `json:"threshold"`
	// Z is the signed modified z-score for a numeric field.
	Z float64 `json:"z"`
	// ExplainedBy names the operator-tagged cohort whose own norm holds this
	// fleet outlier, empty otherwise. An explained outlier raises no finding.
	ExplainedBy string `json:"explained_by,omitempty"`
	// LimitedSample marks a norm drawn from a population too small for MAD.
	LimitedSample bool `json:"limited_sample"`
	// Exact marks an outlier against a numeric norm with zero spread, judged like a string: at least
	// minStringModeMass of the population holds Median exactly and any other value is off it.
	// An exact norm carries no z-score and no band.
	Exact bool `json:"exact,omitempty"`
	// Favorable marks a numeric outlier on the better side of a field with a polarity. It is
	// reported at info severity.
	Favorable bool `json:"favorable,omitempty"`
}

// Basis returns the norm this outlier was measured against. A finding built
// from an outlier takes its NormBasis from here, so the two never disagree.
func (o OutlierResult) Basis() *NormBasis {
	return &NormBasis{
		Scope:         o.Scope,
		Field:         o.Field,
		Kind:          o.Kind,
		Median:        o.Median,
		MAD:           o.MAD,
		Mode:          o.Mode,
		ModeShare:     o.ModeShare,
		Consensus:     slices.Clone(o.Consensus),
		Missing:       slices.Clone(o.Missing),
		SampleSize:    o.SampleSize,
		Threshold:     o.Threshold,
		Value:         o.Value,
		Z:             o.Z,
		LimitedSample: o.LimitedSample,
		Exact:         o.Exact,
		NoWhatIf:      WhatIfRefusal(o.Scanner, o.Field),
	}
}

// DetectOutliers analyzes a report and returns clusters that deviate from fleet
// norms. The threshold controls sensitivity for numeric fields: lower values
// flag more outliers. The function only emits findings when the sample is
// large enough to be statistically meaningful (see minMADSample).
func DetectOutliers(r *Report, threshold float64) []OutlierResult {
	outliers, _ := detectOutliers(r.Clusters, r.Sections, threshold, NormScopeFleet)
	return outliers
}

// walkFields flattens every non-uniform section that holds at least minPerCluster clusters over
// clusters, applies the set projections and availability gate, and calls visit once per field
// the detectors compare, with the flattened values for that section.
func walkFields(clusters []string, sections map[string]*SectionReport, minPerCluster int,
	visit func(scannerName, field string, flat map[string]map[string]any)) {
	for scannerName, sec := range sections {
		if sec.Uniform || len(sec.PerCluster) < minPerCluster {
			continue
		}
		flat := flattenSection(clusters, sec)
		prepareFlat(scannerName, flat)
		for _, field := range collectFields(flat) {
			if _, skip := skipFields[field]; skip {
				continue
			}
			visit(scannerName, field, flat)
		}
	}
}

// detectOutliers runs the MAD, set, and mode detectors over clusters, returning the
// distribution behind every field it evaluated as well, and stamps every result and
// distribution with the scope its norm was computed over.
func detectOutliers(clusters []string, sections map[string]*SectionReport,
	threshold float64, scope string) ([]OutlierResult, []Distribution) {
	var outliers []OutlierResult
	var dists []Distribution
	visit := func(scannerName, field string, flat map[string]map[string]any) {
		var found []OutlierResult
		var dist *Distribution
		switch {
		case isNumericInFlat(clusters, flat, field):
			found, dist = detectNumericOutliers(clusters, flat, field, scannerName, threshold)
		case isArrayInFlat(clusters, flat, field):
			found, dist = detectSetOutliers(clusters, flat, field, scannerName)
		default:
			found, dist = detectStringOutliers(clusters, flat, field, scannerName)
		}
		outliers = append(outliers, found...)
		if dist != nil {
			dist.Scanner = scannerName
			dist.Field = field
			dists = append(dists, *dist)
		}
	}
	walkFields(clusters, sections, minMADSample, visit)

	for i := range outliers {
		outliers[i].Scope = scope
	}
	for i := range dists {
		dists[i].Scope = scope
	}
	sortOutliers(outliers)
	sortDistributions(dists)
	return outliers, dists
}

// sortOutliers orders outliers by severity, then scanner, cluster, and field,
// so report output is stable across runs.
func sortOutliers(outliers []OutlierResult) {
	sort.Slice(outliers, func(i, j int) bool {
		si, sj := util.SeverityRank(outliers[i].Severity), util.SeverityRank(outliers[j].Severity)
		if si != sj {
			return si > sj
		}
		if outliers[i].Scanner != outliers[j].Scanner {
			return outliers[i].Scanner < outliers[j].Scanner
		}
		if outliers[i].Cluster != outliers[j].Cluster {
			return outliers[i].Cluster < outliers[j].Cluster
		}
		return outliers[i].Field < outliers[j].Field
	})
}

// detectNumericOutliers flags clusters where a numeric field is beyond threshold
// modified z-scores from the fleet median. Uses MAD (median absolute deviation),
// which is robust to the outliers themselves. When MAD is zero the population
// is uniform enough that a single non-median value is not statistically
// distinguishable from noise; we emit nothing in that case rather than flagging
// every minority value. The distribution is returned whenever the population
// reaches minMADSample, flagged or not, with every Z zero when MAD is zero.
func detectNumericOutliers(clusters []string, flat map[string]map[string]any, field, scannerName string,
	threshold float64) ([]OutlierResult, *Distribution) {
	vals := make([]float64, 0, len(clusters))
	clusterVals := make(map[string]float64, len(clusters))
	var order []string
	for _, c := range clusters {
		m := flat[c]
		if m == nil {
			continue
		}
		v, ok := util.Float64(m[field])
		if !ok {
			continue
		}
		vals = append(vals, v)
		clusterVals[c] = v
		order = append(order, c)
	}

	if len(vals) < minMADSample {
		return nil, nil
	}

	median := util.Median(vals)
	mad := computeMAD(vals, median)
	dist := &Distribution{
		Kind:       NormKindNumeric,
		Values:     make([]ClusterValue, 0, len(order)),
		Median:     median,
		MAD:        mad,
		Threshold:  threshold,
		SampleSize: len(vals),
	}
	for _, c := range order {
		v := clusterVals[c]
		cv := ClusterValue{Cluster: c, Number: &v}
		if mad != 0 {
			cv.Z = cappedZ(madScale * (v - median) / mad)
		}
		dist.Values = append(dist.Values, cv)
	}

	if mad == 0 {
		return exactOutliers(order, clusterVals, median, field, scannerName, dist), dist
	}
	dist.Band = threshold * mad / madScale

	var outliers []OutlierResult
	for c, v := range clusterVals {
		zScore := cappedZ(madScale * (v - median) / mad)
		absZ := math.Abs(zScore)
		if absZ > threshold {
			sev, favorable := numericSeverity(scannerName, field, v-median)
			outliers = append(outliers, OutlierResult{
				Cluster:    c,
				Field:      field,
				Value:      formatNum(v),
				FleetNorm:  formatNum(median),
				Deviation:  absZ,
				Scanner:    scannerName,
				Severity:   sev,
				Favorable:  favorable,
				Kind:       NormKindNumeric,
				Median:     median,
				MAD:        mad,
				SampleSize: len(vals),
				Threshold:  threshold,
				Z:          zScore,
			})
		}
	}
	markOutliers(dist, outliers, false)
	dist.Mass = massOf(*dist)
	return outliers, dist
}

// exactOutliers judges a numeric field whose MAD is zero like a string field: when at least
// minStringModeMass of the population holds the median exactly, every cluster off it is an
// outlier with an exact norm and no z-score. Below that share nothing is flagged. It marks
// dist as exact and sets its share and mass.
func exactOutliers(order []string, clusterVals map[string]float64, median float64, field,
	scannerName string, dist *Distribution) []OutlierResult {
	atMedian := 0
	for _, c := range order {
		if clusterVals[c] == median {
			atMedian++
		}
	}
	share := float64(atMedian) / float64(len(order))
	dist.Exact = true
	dist.ModeShare = share
	dist.Threshold = minStringModeMass
	if share < minStringModeMass {
		return nil
	}
	var outliers []OutlierResult
	for _, c := range order {
		v := clusterVals[c]
		if v == median {
			continue
		}
		sev, favorable := numericSeverity(scannerName, field, v-median)
		outliers = append(outliers, OutlierResult{
			Cluster:    c,
			Field:      field,
			Value:      formatNum(v),
			FleetNorm:  formatNum(median),
			Scanner:    scannerName,
			Severity:   sev,
			Favorable:  favorable,
			Kind:       NormKindNumeric,
			Median:     median,
			ModeShare:  share,
			SampleSize: len(order),
			Threshold:  minStringModeMass,
			Exact:      true,
		})
	}
	markOutliers(dist, outliers, false)
	dist.Mass = massOf(*dist)
	return outliers
}

// cappedZ returns z with an infinite value replaced by the signed
// maxReportedDeviation, so a distribution stays JSON-safe.
func cappedZ(z float64) float64 {
	if math.IsInf(z, 0) {
		return math.Copysign(maxReportedDeviation, z)
	}
	return z
}

// detectStringOutliers flags clusters whose string value differs from the mode,
// but only when the mode commands at least minStringModeMass of the population.
// Tied or near-tied distributions produce no findings to avoid arbitrary
// majority-vs-minority reports.
func detectStringOutliers(clusters []string, flat map[string]map[string]any, field, scannerName string) ([]OutlierResult, *Distribution) {
	counts := make(map[string]int)
	clusterVals := make(map[string]string, len(clusters))
	var order []string

	for _, c := range clusters {
		raw, ok := flat[c][field]
		if !ok || raw == nil {
			continue
		}
		v := fmt.Sprintf("%v", raw)
		counts[v]++
		clusterVals[c] = v
		order = append(order, c)
	}

	if len(counts) <= 1 || len(clusterVals) == 0 {
		return nil, nil
	}

	mode := dominantString(counts)
	share := float64(counts[mode]) / float64(len(clusterVals))
	dist := &Distribution{
		Kind:       NormKindString,
		Values:     make([]ClusterValue, 0, len(order)),
		Threshold:  minStringModeMass,
		Mode:       mode,
		ModeShare:  share,
		SampleSize: len(clusterVals),
	}
	for _, c := range order {
		dist.Values = append(dist.Values, ClusterValue{Cluster: c, Text: clusterVals[c]})
	}
	if mode == "" || share < minStringModeMass {
		return nil, dist
	}

	var outliers []OutlierResult
	for c, v := range clusterVals {
		if v != mode {
			outliers = append(outliers, OutlierResult{
				Cluster:    c,
				Field:      field,
				Value:      v,
				FleetNorm:  mode,
				Scanner:    scannerName,
				Severity:   classifySeverity(scannerName, field),
				Kind:       NormKindString,
				Mode:       mode,
				ModeShare:  share,
				SampleSize: len(clusterVals),
				Threshold:  minStringModeMass,
			})
		}
	}
	markOutliers(dist, outliers, false)
	return outliers, dist
}

// dominantString returns the mode of a string population. Ties break
// deterministically by smallest string so callers get stable output.
func dominantString(counts map[string]int) string {
	var mode string
	best := 0
	for v, n := range counts {
		if n > best || (n == best && v < mode) {
			mode = v
			best = n
		}
	}
	return mode
}

// detectSetOutliers flags clusters missing items present in the consensus set.
// Consensus requires an item to appear in at least minSetConsensusShare of
// clusters, using a share rather than an integer-divide threshold so the
// cutoff has no discontinuity at small N. A cluster that does not report the field at
// all is left out of the population; a null list counts as an empty set.
func detectSetOutliers(clusters []string, flat map[string]map[string]any, field, scannerName string) ([]OutlierResult, *Distribution) {
	itemCounts := make(map[string]int)
	clusterSets := make(map[string]map[string]struct{}, len(clusters))
	var order []string

	for _, c := range clusters {
		m := flat[c]
		if m == nil {
			continue
		}
		v, present := m[field]
		if !present {
			continue
		}
		arr, _ := v.([]any)
		set := make(map[string]struct{})
		for _, item := range arr {
			s := fmt.Sprintf("%v", item)
			set[s] = struct{}{}
			itemCounts[s]++
		}
		clusterSets[c] = set
		order = append(order, c)
	}

	if len(clusterSets) == 0 {
		return nil, nil
	}

	threshold := int(math.Ceil(float64(len(clusterSets)) * minSetConsensusShare))
	var consensus []string
	for item, count := range itemCounts {
		if count >= threshold {
			consensus = append(consensus, item)
		}
	}
	sort.Strings(consensus)

	dist := &Distribution{
		Kind:       NormKindSet,
		Values:     make([]ClusterValue, 0, len(order)),
		Threshold:  minSetConsensusShare,
		Consensus:  consensus,
		SampleSize: len(clusterSets),
	}
	var outliers []OutlierResult
	for _, c := range order {
		set := clusterSets[c]
		var missing []string
		for _, item := range consensus {
			if _, ok := set[item]; !ok {
				missing = append(missing, item)
			}
		}
		dist.Values = append(dist.Values, ClusterValue{
			Cluster: c, Size: len(set), Missing: missing, Outlier: len(missing) > 0,
		})
		if len(missing) > 0 {
			outliers = append(outliers, OutlierResult{
				Cluster:    c,
				Field:      field,
				Value:      fmt.Sprintf("missing %d: %v", len(missing), missing),
				FleetNorm:  fmt.Sprintf("%d consensus items", len(consensus)),
				Scanner:    scannerName,
				Severity:   classifySeverity(scannerName, field),
				Kind:       NormKindSet,
				Consensus:  slices.Clone(consensus),
				Missing:    slices.Clone(missing),
				SampleSize: len(clusterSets),
				Threshold:  minSetConsensusShare,
			})
		}
	}
	return outliers, dist
}

// setProjection turns an array of objects into the member set the set
// detector compares. The raw array stays in skipFields, so only the projected
// member names reach the detector.
type setProjection struct {
	// From is the array field the scanner reports.
	From string
	// To is the field the member set is published under.
	To string
	// Member returns the member an item names, or "" when the item names none.
	Member func(item map[string]any) string
	// SkipEmpty leaves a cluster with no named members out of the population,
	// for sets that describe how a resource is used rather than which exist.
	SkipEmpty bool
	// Build turns a member back into the object a what-if adds to the raw
	// array. Nil when a member does not say enough to build one, as an
	// ingress class does not name an ingress.
	Build func(member string) map[string]any
}

// memberOf returns a Member func that joins the string values of keys with
// "/", or returns "" when any of them is missing or empty.
func memberOf(keys ...string) func(map[string]any) string {
	return func(item map[string]any) string {
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			s, _ := item[k].(string)
			if s == "" {
				return ""
			}
			parts = append(parts, s)
		}
		return strings.Join(parts, "/")
	}
}

// prepareFlat rewrites flattened scanner data in place for the outlier
// detectors: it adds the projected member set of a projected array field and
// drops the counts of an availability-gated scanner on clusters where its
// feature is not installed.
func prepareFlat(scannerName string, flat map[string]map[string]any) {
	if p, ok := setProjections[scannerName]; ok {
		for _, m := range flat {
			v, present := m[p.From]
			if !present {
				continue
			}
			raw, _ := v.([]any)
			seen := make(map[string]struct{}, len(raw))
			members := make([]any, 0, len(raw))
			for _, item := range raw {
				obj, ok := item.(map[string]any)
				if !ok {
					continue
				}
				name := p.Member(obj)
				if name == "" {
					continue
				}
				if _, dup := seen[name]; dup {
					continue
				}
				seen[name] = struct{}{}
				members = append(members, name)
			}
			if len(members) == 0 && p.SkipEmpty {
				continue
			}
			m[p.To] = members
		}
	}
	if _, ok := availabilityGated[scannerName]; ok {
		for _, m := range flat {
			if available, _ := m["available"].(bool); available {
				continue
			}
			for k, v := range m {
				if _, numeric := v.(float64); numeric {
					delete(m, k)
				}
			}
		}
	}
}

// flattenSection converts per-cluster data to maps of JSON fields.
func flattenSection(clusters []string, sec *SectionReport) map[string]map[string]any {
	flat := make(map[string]map[string]any, len(clusters))
	for _, c := range clusters {
		data, ok := sec.PerCluster[c]
		if !ok {
			continue
		}
		m, shared := genericMap(data)
		if shared {
			m = maps.Clone(m)
		}
		flat[c] = m
	}
	return flat
}

// genericMap returns data as a map[string]any, or nil when it does not convert. A map that
// already holds only the value types JSON decoding produces is returned as is and shared reports
// true. Anything else takes one JSON round trip, so numbers become float64 and slices []any.
func genericMap(data any) (m map[string]any, shared bool) {
	if m, ok := data.(map[string]any); ok && jsonShaped(m) {
		return m, true
	}
	b, err := json.Marshal(data)
	if err != nil {
		return nil, false
	}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, false
	}
	return m, false
}

// jsonShaped reports whether v holds only the types encoding/json decodes into an any: nil,
// bool, string, finite float64, []any, and map[string]any.
func jsonShaped(v any) bool {
	switch t := v.(type) {
	case nil, bool, string:
		return true
	case float64:
		return !math.IsNaN(t) && !math.IsInf(t, 0)
	case []any:
		for _, e := range t {
			if !jsonShaped(e) {
				return false
			}
		}
		return true
	case map[string]any:
		for _, e := range t {
			if !jsonShaped(e) {
				return false
			}
		}
		return true
	default:
		return false
	}
}

// collectFields gathers unique field names across all clusters.
func collectFields(flat map[string]map[string]any) []string {
	seen := make(map[string]struct{})
	for _, m := range flat {
		for k := range m {
			seen[k] = struct{}{}
		}
	}
	fields := make([]string, 0, len(seen))
	for f := range seen {
		fields = append(fields, f)
	}
	sort.Strings(fields)
	return fields
}

// isNumericInFlat reports whether a field is numeric in at least one cluster
// and not non-numeric in any cluster. Every cluster is consulted, so a leading
// nil does not classify an otherwise numeric field as non-numeric.
func isNumericInFlat(clusters []string, flat map[string]map[string]any, field string) bool {
	sawNumeric := false
	for _, c := range clusters {
		m := flat[c]
		if m == nil {
			continue
		}
		v, present := m[field]
		if !present || v == nil {
			continue
		}
		if _, ok := v.(float64); ok {
			sawNumeric = true
			continue
		}
		return false
	}
	return sawNumeric
}

// isArrayInFlat reports whether a field is an array in at least one cluster
// and not a non-array in any cluster.
func isArrayInFlat(clusters []string, flat map[string]map[string]any, field string) bool {
	sawArray := false
	for _, c := range clusters {
		m := flat[c]
		if m == nil {
			continue
		}
		v, present := m[field]
		if !present || v == nil {
			continue
		}
		if _, ok := v.([]any); ok {
			sawArray = true
			continue
		}
		return false
	}
	return sawArray
}

// computeMAD returns the median absolute deviation from the median.
func computeMAD(vals []float64, median float64) float64 {
	deviations := make([]float64, len(vals))
	for i, v := range vals {
		deviations[i] = math.Abs(v - median)
	}
	return util.Median(deviations)
}
