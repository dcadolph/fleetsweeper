package report

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/cohort"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Fix kinds name what a what-if does to one cluster's field.
const (
	// FixMedian sets a numeric field to the scope median.
	FixMedian = "median"
	// FixMode sets a string field to the scope mode.
	FixMode = "mode"
	// FixConsensus adds the consensus members a set field lacks.
	FixConsensus = "consensus"
	// FixRemove takes the cluster out of the population entirely.
	FixRemove = "remove"
)

// Fix describes one hypothetical change to one cluster.
type Fix struct {
	// Cluster is the cluster to change.
	Cluster string `json:"cluster"`
	// Scanner is the scanner whose field changes.
	Scanner string `json:"scanner"`
	// Field is the field to change, as distributions name it.
	Field string `json:"field"`
	// Kind is one of the Fix constants. Empty picks the one that matches the
	// field: median for numeric, mode for string, consensus for set.
	Kind string `json:"kind,omitempty"`
	// Scope is "fleet" or a cohort name, the norm to fix toward. Empty means
	// the cluster's tagged cohort when that cohort has a norm for the field,
	// since that is the norm the cluster answers to, and the fleet otherwise.
	Scope string `json:"scope,omitempty"`
}

// Outcome is what the fleet would look like after a Fix. Nothing is written:
// the report is rebuilt from a patched copy of the scan results.
type Outcome struct {
	// Fix is the change, with Kind and Scope resolved.
	Fix Fix `json:"fix"`
	// ScoreBefore is the fleet score as scanned.
	ScoreBefore int `json:"score_before"`
	// ScoreAfter is the fleet score after the fix.
	ScoreAfter int `json:"score_after"`
	// Before is the field's distribution as scanned.
	Before *Distribution `json:"before"`
	// After is the field's distribution after the fix, nil when every
	// cluster now agrees or the population no longer qualifies for one.
	After *Distribution `json:"after,omitempty"`
	// MedianShift is the change in the numeric median.
	MedianShift float64 `json:"median_shift"`
	// MADShift is the change in the numeric MAD.
	MADShift float64 `json:"mad_shift"`
	// NewOutliers lists clusters flagged on the field after the fix that were
	// not flagged before, sorted.
	NewOutliers []string `json:"new_outliers,omitempty"`
	// ClearedOutliers lists clusters flagged before that are not flagged
	// after, sorted.
	ClearedOutliers []string `json:"cleared_outliers,omitempty"`
}

// defaultFixScope returns the tagged cohort of the fix's cluster when that
// cohort has a distribution for the field holding the cluster, else the fleet.
func defaultFixScope(r *Report, fix Fix) string {
	for _, c := range r.Cohorts {
		if c.Source != string(cohort.SourceTagged) || !slices.Contains(c.Clusters, fix.Cluster) {
			continue
		}
		if d := distributionFor(r, c.Name, fix.Scanner, fix.Field); d != nil &&
			slices.ContainsFunc(d.Values, func(v ClusterValue) bool { return v.Cluster == fix.Cluster }) {
			return c.Name
		}
	}
	return NormScopeFleet
}

// WhatIf builds the report for clusters and results, applies fix to a copy of
// the results, rebuilds, and returns how the score and the field's norm move.
// results is not modified.
func WhatIf(clusters []string, results map[string]map[string]scanner.Result, opts BuildOptions, fix Fix) (Outcome, error) {
	before := Build(clusters, results, opts)
	if fix.Scope == "" {
		fix.Scope = defaultFixScope(before, fix)
	}
	dist := distributionFor(before, fix.Scope, fix.Scanner, fix.Field)
	if dist == nil {
		return Outcome{}, fmt.Errorf("%w: no %s distribution for %s/%s", ErrWhatIf, fix.Scope, fix.Scanner, fix.Field)
	}
	idx := slices.IndexFunc(dist.Values, func(v ClusterValue) bool { return v.Cluster == fix.Cluster })
	if idx < 0 {
		return Outcome{}, fmt.Errorf("%w: %s is not in the %s population for %s/%s",
			ErrWhatIf, fix.Cluster, fix.Scope, fix.Scanner, fix.Field)
	}
	if fix.Kind == "" {
		fix.Kind = map[string]string{NormKindNumeric: FixMedian, NormKindString: FixMode, NormKindSet: FixConsensus}[dist.Kind]
	}

	patchedClusters, patched, err := applyFix(clusters, results, fix, dist, dist.Values[idx])
	if err != nil {
		return Outcome{}, err
	}
	after := Build(patchedClusters, patched, opts)

	out := Outcome{
		Fix:         fix,
		ScoreBefore: before.FleetScore.Score,
		ScoreAfter:  after.FleetScore.Score,
		Before:      dist,
		After:       distributionFor(after, fix.Scope, fix.Scanner, fix.Field),
	}
	flaggedAfter := map[string]bool{}
	if out.After != nil {
		out.MedianShift = out.After.Median - dist.Median
		out.MADShift = out.After.MAD - dist.MAD
		for _, v := range out.After.Values {
			flaggedAfter[v.Cluster] = v.Outlier
		}
	}
	for _, v := range dist.Values {
		if v.Outlier && !flaggedAfter[v.Cluster] {
			out.ClearedOutliers = append(out.ClearedOutliers, v.Cluster)
		}
	}
	if out.After != nil {
		flaggedBefore := map[string]bool{}
		for _, v := range dist.Values {
			flaggedBefore[v.Cluster] = v.Outlier
		}
		for _, v := range out.After.Values {
			if v.Outlier && !flaggedBefore[v.Cluster] {
				out.NewOutliers = append(out.NewOutliers, v.Cluster)
			}
		}
	}
	sort.Strings(out.NewOutliers)
	sort.Strings(out.ClearedOutliers)
	return out, nil
}

// distributionFor returns a copy of r's distribution for scope, scanner, and
// field, or nil when there is none.
func distributionFor(r *Report, scope, scannerName, field string) *Distribution {
	for _, d := range r.Distributions {
		if d.Scope == scope && d.Scanner == scannerName && d.Field == field {
			d := d
			return &d
		}
	}
	return nil
}

// applyFix returns copies of clusters and results with fix applied, using dist
// and the cluster's current value cv for the norm to fix toward. Only the one
// touched scanner result is rewritten; every other result is shared.
func applyFix(clusters []string, results map[string]map[string]scanner.Result, fix Fix, dist *Distribution,
	cv ClusterValue) ([]string, map[string]map[string]scanner.Result, error) {
	patched := make(map[string]map[string]scanner.Result, len(results))
	for c, byScanner := range results {
		patched[c] = byScanner
	}
	if fix.Kind == FixRemove {
		delete(patched, fix.Cluster)
		kept := slices.DeleteFunc(slices.Clone(clusters), func(c string) bool { return c == fix.Cluster })
		return kept, patched, nil
	}

	res, ok := results[fix.Cluster][fix.Scanner]
	if !ok {
		return nil, nil, fmt.Errorf("%w: %s has no %s result", ErrWhatIf, fix.Cluster, fix.Scanner)
	}
	data, err := dataMap(res.Data)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %s %s data: %w", ErrWhatIf, fix.Cluster, fix.Scanner, err)
	}

	switch {
	case fix.Kind == FixMedian && dist.Kind == NormKindNumeric:
		data[fix.Field] = dist.Median
	case fix.Kind == FixMode && dist.Kind == NormKindString:
		v, err := modeValue(results, fix, dist.Mode)
		if err != nil {
			return nil, nil, err
		}
		data[fix.Field] = v
	case fix.Kind == FixConsensus && dist.Kind == NormKindSet:
		if err := addMembers(data, fix, cv.Missing); err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("%w: fix %q does not apply to %s field %s/%s",
			ErrWhatIf, fix.Kind, dist.Kind, fix.Scanner, fix.Field)
	}

	byScanner := make(map[string]scanner.Result, len(results[fix.Cluster]))
	for name, r := range results[fix.Cluster] {
		byScanner[name] = r
	}
	res.Data = data
	byScanner[fix.Scanner] = res
	patched[fix.Cluster] = byScanner
	return clusters, patched, nil
}

// dataMap returns a scanner payload as a fresh JSON object map, so a fix can
// rewrite one field of any payload type without touching the original.
func dataMap(data any) (map[string]any, error) {
	b, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	if m == nil {
		m = map[string]any{}
	}
	return m, nil
}

// modeValue returns the raw value of fix.Field on a cluster whose value
// formats as mode, so a fix copies the norm's type as well as its text.
func modeValue(results map[string]map[string]scanner.Result, fix Fix, mode string) (any, error) {
	names := make([]string, 0, len(results))
	for c := range results {
		names = append(names, c)
	}
	sort.Strings(names)
	for _, c := range names {
		res, ok := results[c][fix.Scanner]
		if !ok || c == fix.Cluster {
			continue
		}
		m, err := dataMap(res.Data)
		if err != nil {
			continue
		}
		if v, ok := m[fix.Field]; ok && fmt.Sprintf("%v", v) == mode {
			return v, nil
		}
	}
	return nil, fmt.Errorf("%w: no cluster holds the mode %q of %s/%s", ErrWhatIf, mode, fix.Scanner, fix.Field)
}

// addMembers adds the missing consensus members to a set field. A projected
// field adds objects to the raw array it was projected from; a plain array
// field appends the members. A projection whose members cannot be turned
// back into objects without inventing data is refused.
func addMembers(data map[string]any, fix Fix, missing []string) error {
	p, projected := setProjections[fix.Scanner]
	if !projected || p.To != fix.Field {
		arr, _ := data[fix.Field].([]any)
		for _, m := range missing {
			arr = append(arr, m)
		}
		data[fix.Field] = arr
		return nil
	}
	if p.Build == nil {
		return fmt.Errorf("%w: adding %s to %s/%s would invent the objects that carry them",
			ErrWhatIf, fix.Field, fix.Scanner, p.From)
	}
	arr, _ := data[p.From].([]any)
	for _, m := range missing {
		arr = append(arr, p.Build(m))
	}
	data[p.From] = arr
	return nil
}

// memberObject returns a Build func that splits a member on "/" into keys,
// the inverse of memberOf for the same keys.
func memberObject(keys ...string) func(string) map[string]any {
	return func(member string) map[string]any {
		parts := strings.SplitN(member, "/", len(keys))
		obj := make(map[string]any, len(keys))
		for i, k := range keys {
			if i < len(parts) {
				obj[k] = parts[i]
			}
		}
		return obj
	}
}
