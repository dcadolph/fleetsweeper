package report

import (
	"sort"

	"github.com/dcadolph/fleetsweeper/internal/util"
)

// Persistence classes describe how consistently a finding recurs across a
// window of scans. The data carries no operator resolution label, so recurrence
// across scans is the strongest learned signal available for whether a finding
// is a standing problem worth attention or a transient blip.
const (
	// PersistenceChronic marks a finding present in most scans in the window.
	PersistenceChronic = "chronic"
	// PersistenceIntermittent marks a finding that comes and goes.
	PersistenceIntermittent = "intermittent"
	// PersistenceTransient marks a finding seen in only a few scans.
	PersistenceTransient = "transient"
)

// Recurrence fraction thresholds separating the three persistence classes.
const (
	chronicFraction   = 0.7
	transientFraction = 0.3
)

// FindingPersistence summarizes how often one finding recurred across a window
// of scans. It is an implicit, unsupervised severity signal: a critical that
// recurs in every scan is a standing problem, while one seen once is likely
// noise or an already-resolved blip.
type FindingPersistence struct {
	// Fingerprint is the stable finding identifier, matching its ack key.
	Fingerprint string `json:"fingerprint"`
	// Cluster is the finding's cluster scope, or "fleet".
	Cluster string `json:"cluster"`
	// Scanner is the scanner that produced the finding.
	Scanner string `json:"scanner"`
	// Title is the finding title as last observed.
	Title string `json:"title"`
	// Severity is the finding's severity as last observed.
	Severity string `json:"severity"`
	// Present is the number of scans in the window that contained the finding.
	Present int `json:"present"`
	// Total is the number of scans in the window.
	Total int `json:"total"`
	// Fraction is Present divided by Total, in the range zero to one.
	Fraction float64 `json:"fraction"`
	// Streak is the number of consecutive most-recent scans containing it.
	Streak int `json:"streak"`
	// Class is chronic, intermittent, or transient.
	Class string `json:"class"`
	// Acked reports whether the finding has an active acknowledgement.
	Acked bool `json:"acked"`
}

// ComputePersistence classifies each distinct finding by how often it recurred
// across series, a slice of per-scan finding sets ordered oldest to newest.
// acked holds the fingerprints with an active acknowledgement. Results are
// sorted most-persistent first, then by severity, cluster, and title, so the
// standing problems lead. An empty series yields no results.
func ComputePersistence(series [][]Finding, acked map[string]bool) []FindingPersistence {
	total := len(series)
	if total == 0 {
		return nil
	}

	type agg struct {
		cluster, scanner, title, severity string
		present                           int
	}
	seen := make(map[string]*agg)
	order := make([]string, 0)

	for _, scan := range series {
		// Collapse duplicate titles within a single scan so a finding repeated
		// in one scan still counts as one presence for that scan.
		inScan := make(map[string]bool)
		for _, f := range scan {
			fp := util.Fingerprint(f.Cluster, f.Scanner, f.Title)
			if inScan[fp] {
				continue
			}
			inScan[fp] = true
			a := seen[fp]
			if a == nil {
				a = &agg{cluster: f.Cluster, scanner: f.Scanner}
				seen[fp] = a
				order = append(order, fp)
			}
			a.present++
			a.severity = f.Severity
			a.title = f.Title
		}
	}

	out := make([]FindingPersistence, 0, len(order))
	for _, fp := range order {
		a := seen[fp]
		frac := float64(a.present) / float64(total)
		out = append(out, FindingPersistence{
			Fingerprint: fp,
			Cluster:     a.cluster,
			Scanner:     a.scanner,
			Title:       a.title,
			Severity:    a.severity,
			Present:     a.present,
			Total:       total,
			Fraction:    frac,
			Streak:      recentStreak(series, fp),
			Class:       persistenceClass(frac),
			Acked:       acked[fp],
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Fraction != out[j].Fraction {
			return out[i].Fraction > out[j].Fraction
		}
		si, sj := persistSeverityRank(out[i].Severity), persistSeverityRank(out[j].Severity)
		if si != sj {
			return si < sj
		}
		if out[i].Cluster != out[j].Cluster {
			return out[i].Cluster < out[j].Cluster
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// recentStreak counts consecutive most-recent scans that contain the
// fingerprint, a stronger "still happening" signal than the raw fraction.
func recentStreak(series [][]Finding, fp string) int {
	streak := 0
	for i := len(series) - 1; i >= 0; i-- {
		found := false
		for _, f := range series[i] {
			if util.Fingerprint(f.Cluster, f.Scanner, f.Title) == fp {
				found = true
				break
			}
		}
		if !found {
			break
		}
		streak++
	}
	return streak
}

// persistenceClass maps a recurrence fraction to a class label.
func persistenceClass(fraction float64) string {
	switch {
	case fraction >= chronicFraction:
		return PersistenceChronic
	case fraction <= transientFraction:
		return PersistenceTransient
	default:
		return PersistenceIntermittent
	}
}

// persistSeverityRank orders severities most-severe first for stable sorting.
func persistSeverityRank(sev string) int {
	switch sev {
	case SeverityCritical:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}
