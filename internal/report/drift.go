package report

import (
	"fmt"
	"math"
	"sort"
)

// maxDriftFields is how many moved fields a ledger row lists.
const maxDriftFields = 5

// ScanReport pairs a report with the ID of the scan it was built from.
type ScanReport struct {
	// ID is the scan ID. It may be empty when the report was not stored.
	ID string
	// Report is the report built from the scan.
	Report *Report
}

// Ledger records which clusters drifted across a run of scans and why: how
// their deviation mass moved, which of their values changed, and which
// outlier flags they gained or lost, read from the fleet-scope distributions.
// A cluster drifted when one of its own values changed or a flag flipped; a
// cluster whose z moved only because the norm moved under it is left out.
type Ledger struct {
	// Scans lists the scan IDs the ledger spans, oldest first.
	Scans []string `json:"scans"`
	// Clusters lists the clusters that drifted, largest change in deviation
	// mass first.
	Clusters []ClusterDrift `json:"clusters"`
}

// ClusterDrift is one cluster's row in a Ledger.
type ClusterDrift struct {
	// Cluster is the cluster name.
	Cluster string `json:"cluster"`
	// Mass is the cluster's deviation mass in each scan, oldest first, zero
	// where the cluster was absent.
	Mass []float64 `json:"mass"`
	// MassBefore is the deviation mass in the first scan.
	MassBefore float64 `json:"mass_before"`
	// MassAfter is the deviation mass in the last scan.
	MassAfter float64 `json:"mass_after"`
	// MassDelta is MassAfter - MassBefore.
	MassDelta float64 `json:"mass_delta"`
	// Fields lists up to five fields whose value changed between the first
	// and last scan, the largest move in |z| first.
	Fields []FieldDrift `json:"fields,omitempty"`
	// Gained lists outlier flags set in the last scan and not in the first.
	Gained []FlagChange `json:"gained,omitempty"`
	// Lost lists outlier flags set in the first scan and not in the last.
	Lost []FlagChange `json:"lost,omitempty"`
}

// FieldDrift is one field's movement for one cluster.
type FieldDrift struct {
	// Scanner is the scanner that reported the field.
	Scanner string `json:"scanner"`
	// Field is the field name.
	Field string `json:"field"`
	// ZBefore is the cluster's z in the first scan, zero when absent.
	ZBefore float64 `json:"z_before"`
	// ZAfter is the cluster's z in the last scan, zero when absent.
	ZAfter float64 `json:"z_after"`
	// Before is the cluster's value in the first scan, empty when absent.
	Before string `json:"before,omitempty"`
	// After is the cluster's value in the last scan, empty when absent.
	After string `json:"after,omitempty"`
}

// FlagChange is one outlier flag that changed state over the ledger.
type FlagChange struct {
	// Scanner is the scanner that reported the field.
	Scanner string `json:"scanner"`
	// Field is the field name.
	Field string `json:"field"`
	// Scan is the ID of the scan where the flag last changed to its final
	// state.
	Scan string `json:"scan"`
}

// fieldKey identifies a field across reports.
type fieldKey struct {
	// scanner is the scanner name.
	scanner string
	// field is the field name.
	field string
}

// DriftLedger builds the ledger over scans, which must be ordered oldest
// first. A single scan or none yields a ledger with no drift.
func DriftLedger(scans []ScanReport) Ledger {
	l := Ledger{Scans: make([]string, 0, len(scans)), Clusters: []ClusterDrift{}}
	for _, s := range scans {
		l.Scans = append(l.Scans, s.ID)
	}
	if len(scans) < 2 {
		return l
	}

	values := make([]map[fieldKey]map[string]ClusterValue, len(scans))
	var clusters []string
	seen := map[string]bool{}
	for i, s := range scans {
		values[i] = fleetValues(s.Report)
		if s.Report == nil {
			continue
		}
		for _, c := range s.Report.Clusters {
			if !seen[c] {
				seen[c] = true
				clusters = append(clusters, c)
			}
		}
	}
	first, last := 0, len(scans)-1

	for _, c := range clusters {
		row := ClusterDrift{Cluster: c, Mass: make([]float64, len(scans))}
		for i, s := range scans {
			if s.Report != nil {
				row.Mass[i] = s.Report.DeviationMass[c]
			}
		}
		row.MassBefore, row.MassAfter = row.Mass[first], row.Mass[last]
		row.MassDelta = row.MassAfter - row.MassBefore
		row.Fields = movedFields(values[first], values[last], c)
		row.Gained, row.Lost = flagChanges(scans, values, c)
		if len(row.Fields) == 0 && len(row.Gained) == 0 && len(row.Lost) == 0 {
			continue
		}
		l.Clusters = append(l.Clusters, row)
	}
	sort.SliceStable(l.Clusters, func(i, j int) bool {
		a, b := l.Clusters[i], l.Clusters[j]
		if math.Abs(a.MassDelta) != math.Abs(b.MassDelta) {
			return math.Abs(a.MassDelta) > math.Abs(b.MassDelta)
		}
		if na, nb := len(a.Gained)+len(a.Lost), len(b.Gained)+len(b.Lost); na != nb {
			return na > nb
		}
		return a.Cluster < b.Cluster
	})
	return l
}

// fleetValues indexes the fleet-scope distribution values of r by field and
// cluster.
func fleetValues(r *Report) map[fieldKey]map[string]ClusterValue {
	out := map[fieldKey]map[string]ClusterValue{}
	if r == nil {
		return out
	}
	for _, d := range r.Distributions {
		if d.Scope != NormScopeFleet {
			continue
		}
		byCluster := make(map[string]ClusterValue, len(d.Values))
		for _, v := range d.Values {
			byCluster[v.Cluster] = v
		}
		out[fieldKey{scanner: d.Scanner, field: d.Field}] = byCluster
	}
	return out
}

// movedFields returns the fields whose value for cluster changed between
// before and after, the largest change in |z| first, at most maxDriftFields.
func movedFields(before, after map[fieldKey]map[string]ClusterValue, cluster string) []FieldDrift {
	keys := map[fieldKey]bool{}
	for k := range before {
		keys[k] = true
	}
	for k := range after {
		keys[k] = true
	}
	var out []FieldDrift
	for k := range keys {
		b, hasB := before[k][cluster]
		a, hasA := after[k][cluster]
		fd := FieldDrift{Scanner: k.scanner, Field: k.field, ZBefore: b.Z, ZAfter: a.Z}
		if hasB {
			fd.Before = valueText(b)
		}
		if hasA {
			fd.After = valueText(a)
		}
		if fd.Before == fd.After {
			continue
		}
		out = append(out, fd)
	}
	sort.Slice(out, func(i, j int) bool {
		di := math.Abs(math.Abs(out[i].ZAfter) - math.Abs(out[i].ZBefore))
		dj := math.Abs(math.Abs(out[j].ZAfter) - math.Abs(out[j].ZBefore))
		if di != dj {
			return di > dj
		}
		if out[i].Scanner != out[j].Scanner {
			return out[i].Scanner < out[j].Scanner
		}
		return out[i].Field < out[j].Field
	})
	if len(out) > maxDriftFields {
		out = out[:maxDriftFields]
	}
	return out
}

// flagChanges returns the outlier flags cluster gained and lost between the
// first and last scan, each stamped with the scan where it last flipped.
func flagChanges(scans []ScanReport, values []map[fieldKey]map[string]ClusterValue, cluster string) ([]FlagChange, []FlagChange) {
	keys := map[fieldKey]bool{}
	for _, v := range values {
		for k := range v {
			keys[k] = true
		}
	}
	var gained, lost []FlagChange
	last := len(scans) - 1
	for k := range keys {
		start := values[0][k][cluster].Outlier
		end := values[last][k][cluster].Outlier
		if start == end {
			continue
		}
		flip := last
		for i := last; i > 0; i-- {
			if values[i][k][cluster].Outlier != values[i-1][k][cluster].Outlier {
				flip = i
				break
			}
		}
		fc := FlagChange{Scanner: k.scanner, Field: k.field, Scan: scans[flip].ID}
		if end {
			gained = append(gained, fc)
		} else {
			lost = append(lost, fc)
		}
	}
	sortFlags := func(fs []FlagChange) {
		sort.Slice(fs, func(i, j int) bool {
			if fs[i].Scanner != fs[j].Scanner {
				return fs[i].Scanner < fs[j].Scanner
			}
			return fs[i].Field < fs[j].Field
		})
	}
	sortFlags(gained)
	sortFlags(lost)
	return gained, lost
}

// valueText renders a ClusterValue for display: the number, the text, or the
// count of missing set members.
func valueText(v ClusterValue) string {
	switch {
	case v.Number != nil:
		return formatNum(*v.Number)
	case v.Text != "":
		return v.Text
	case len(v.Missing) > 0:
		return fmt.Sprintf("missing %d", len(v.Missing))
	default:
		return fmt.Sprintf("%d members", v.Size)
	}
}
