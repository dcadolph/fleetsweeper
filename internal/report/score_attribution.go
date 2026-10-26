package report

import (
	"fmt"
	"math"
	"sort"

	"github.com/dcadolph/fleetsweeper/internal/util"
)

// Score terms name the cost categories ComputeFleetScore charges.
const (
	TermCriticalFindings = "critical-findings"
	TermWarningFindings  = "warning-findings"
	TermInfoFindings     = "info-findings"
	TermCriticalClusters = "critical-clusters"
	TermDegradedClusters = "degraded-clusters"
	TermVersionSkew      = "version-skew"
	TermWorstNode        = "worst-node"
)

// ScoreAttribution is the full cost ledger behind a FleetScore: every term
// with its raw and capped cost, and every finding or cluster that contributed
// to a term. The applied costs sum to Total, and the score is 100 - Total
// rounded and floored at zero.
type ScoreAttribution struct {
	// Terms lists every term that cost points, in a fixed order.
	Terms []ScoreTerm `json:"terms"`
	// Entries lists every contribution to a term, grouped by term, rule, and
	// cluster.
	Entries []ScoreEntry `json:"entries"`
	// Total is the sum of every term's applied cost.
	Total float64 `json:"total"`
	// ByCluster sums applied cost per cluster. Fleet-wide costs are left out.
	ByCluster map[string]float64 `json:"by_cluster,omitempty"`
	// ByRule sums applied cost per finding rule. Costs not tied to a rule are
	// left out.
	ByRule map[string]float64 `json:"by_rule,omitempty"`
}

// ScoreTerm is one cost category of the fleet score.
type ScoreTerm struct {
	// Term is the category, one of the Term constants.
	Term string `json:"term"`
	// Reason is the driver label for this term.
	Reason string `json:"reason"`
	// Count is how many findings or clusters the term charged.
	Count int `json:"count"`
	// Raw is the cost before the cap.
	Raw float64 `json:"raw"`
	// Cap is the most the term may cost, zero when uncapped.
	Cap float64 `json:"cap,omitempty"`
	// Cost is the points the term removed from the score.
	Cost float64 `json:"cost"`
}

// ScoreEntry is one contribution to a term. When a term is capped every entry
// is scaled by the same factor, so entries of a term sum to its Cost.
type ScoreEntry struct {
	// Term is the category the entry belongs to.
	Term string `json:"term"`
	// Rule is the finding rule charged, empty for costs not tied to a rule.
	Rule string `json:"rule,omitempty"`
	// Cluster is the cluster charged, empty for fleet-wide costs.
	Cluster string `json:"cluster,omitempty"`
	// Raw is the cost before the term's cap.
	Raw float64 `json:"raw"`
	// Cost is the cost after the term's cap.
	Cost float64 `json:"cost"`
}

// ComputeScoreAttribution returns the cost ledger for r. Safe to call on nil;
// returns an empty ledger.
func ComputeScoreAttribution(r *Report) ScoreAttribution {
	var a ScoreAttribution
	if r == nil {
		return a
	}
	a.addFindingTerms(r.Findings)
	a.addClusterHealthTerms(r.ClusterHealths)
	a.addVersionSkewTerm(r.ClusterHealths)
	a.addWorstNodeTerm(r.ClusterHealths)

	for _, t := range a.Terms {
		a.Total += t.Cost
	}
	for _, e := range a.Entries {
		if e.Cluster != "" {
			if a.ByCluster == nil {
				a.ByCluster = make(map[string]float64)
			}
			a.ByCluster[e.Cluster] += e.Cost
		}
		if e.Rule != "" {
			if a.ByRule == nil {
				a.ByRule = make(map[string]float64)
			}
			a.ByRule[e.Rule] += e.Cost
		}
	}
	return a
}

// Drivers returns the top three terms by rounded cost, ties kept in term
// order.
func (a ScoreAttribution) Drivers() []FleetScoreDriver {
	drivers := make([]FleetScoreDriver, 0, len(a.Terms))
	for _, t := range a.Terms {
		drivers = append(drivers, FleetScoreDriver{Reason: t.Reason, Impact: int(math.Round(t.Cost))})
	}
	sort.SliceStable(drivers, func(i, j int) bool {
		return drivers[i].Impact > drivers[j].Impact
	})
	if len(drivers) > 3 {
		drivers = drivers[:3]
	}
	return drivers
}

// addTerm appends a term built from entries whose Raw is set, applying cap
// (zero means none) by scaling every entry by Cost / Raw. Terms that cost
// nothing are skipped.
func (a *ScoreAttribution) addTerm(term, reason string, count int, limit float64, entries []ScoreEntry) {
	var raw float64
	for _, e := range entries {
		raw += e.Raw
	}
	if raw <= 0 {
		return
	}
	cost := raw
	if limit > 0 {
		cost = math.Min(raw, limit)
	}
	scale := cost / raw
	for i := range entries {
		entries[i].Term = term
		entries[i].Cost = entries[i].Raw * scale
	}
	a.Terms = append(a.Terms, ScoreTerm{Term: term, Reason: reason, Count: count, Raw: raw, Cap: limit, Cost: cost})
	a.Entries = append(a.Entries, entries...)
}

// severityTerm prices the findings of one severity.
type severityTerm struct {
	// term is the ledger term the findings charge.
	term string
	// severity is the finding severity priced.
	severity string
	// label names the severity in the driver reason.
	label string
	// per is the cost of one finding.
	per float64
	// limit caps the term's cost.
	limit float64
}

// severityTerms lists the finding terms in ledger order.
var severityTerms = []severityTerm{
	{term: TermCriticalFindings, severity: SeverityCritical, label: "critical", per: scorePerCritical, limit: scoreCriticalCap},
	{term: TermWarningFindings, severity: SeverityWarning, label: "warning", per: scorePerWarning, limit: scoreWarningCap},
	{term: TermInfoFindings, severity: SeverityInfo, label: "info", per: scorePerInfo, limit: scoreInfoCap},
}

// addFindingTerms charges each finding by severity, one entry per rule and
// cluster pair, each severity capped.
func (a *ScoreAttribution) addFindingTerms(findings []Finding) {
	for _, sev := range severityTerms {
		index := make(map[[2]string]int)
		var entries []ScoreEntry
		count := 0
		for _, f := range findings {
			if f.Severity != sev.severity {
				continue
			}
			count++
			key := [2]string{f.Rule, f.Cluster}
			i, ok := index[key]
			if !ok {
				i = len(entries)
				index[key] = i
				entries = append(entries, ScoreEntry{Rule: f.Rule, Cluster: f.Cluster})
			}
			entries[i].Raw += sev.per
		}
		reason := fmt.Sprintf("%d %s finding%s", count, sev.label, util.Plural(count))
		a.addTerm(sev.term, reason, count, sev.limit, entries)
	}
}

// addClusterHealthTerms charges each critical and each degraded or strained
// cluster its share of the fleet-fraction cost, so one bad cluster in three
// costs more than one in thirty.
func (a *ScoreAttribution) addClusterHealthTerms(healths []ClusterHealth) {
	total := len(healths)
	if total == 0 {
		return
	}
	var crit, deg []ScoreEntry
	for _, h := range healths {
		switch h.Status {
		case "critical":
			crit = append(crit, ScoreEntry{Cluster: h.Name, Raw: scoreCriticalFleet / float64(total)})
		case "degraded", "strained":
			deg = append(deg, ScoreEntry{Cluster: h.Name, Raw: scoreDegradedFleet / float64(total)})
		}
	}
	a.addTerm(TermCriticalClusters, fmt.Sprintf("%d of %d cluster%s critical", len(crit), total, util.Plural(total)),
		len(crit), 0, crit)
	a.addTerm(TermDegradedClusters, fmt.Sprintf("%d of %d cluster%s degraded", len(deg), total, util.Plural(total)),
		len(deg), 0, deg)
}

// addVersionSkewTerm charges a fleet-wide cost for Kubernetes version skew,
// using the severity calibration of VersionSkewSeverity.
func (a *ScoreAttribution) addVersionSkewTerm(healths []ClusterHealth) {
	if len(healths) < 2 {
		return
	}
	versions := make([]string, 0, len(healths))
	for _, h := range healths {
		if h.KubernetesVersion != "" {
			versions = append(versions, h.KubernetesVersion)
		}
	}
	switch VersionSkewSeverity(versions) {
	case SeverityCritical:
		a.addTerm(TermVersionSkew, "Kubernetes version skew exceeds one minor", 1, 0,
			[]ScoreEntry{{Rule: "version/skew", Raw: scoreVersionCritSev}})
	case SeverityWarning:
		a.addTerm(TermVersionSkew, "Kubernetes version skew across the fleet", 1, 0,
			[]ScoreEntry{{Rule: "version/skew", Raw: scoreVersionWarnSev}})
	}
}

// addWorstNodeTerm charges the fleet by the cluster with the worst
// unhealthy-node ratio, so one cluster melting down is not hidden by a
// healthy long tail. Ties go to the first cluster.
func (a *ScoreAttribution) addWorstNodeTerm(healths []ClusterHealth) {
	var worstFrac float64
	var worstCluster string
	for _, h := range healths {
		if h.NodeCount <= 0 {
			continue
		}
		unhealthy := h.NodeCount - h.HealthyNodes
		if unhealthy <= 0 {
			continue
		}
		if frac := float64(unhealthy) / float64(h.NodeCount); frac > worstFrac {
			worstFrac = frac
			worstCluster = h.Name
		}
	}
	if worstFrac == 0 {
		return
	}
	reason := fmt.Sprintf("%s has %d%% unhealthy nodes", worstCluster, int(math.Round(worstFrac*100)))
	a.addTerm(TermWorstNode, reason, 1, 0, []ScoreEntry{{Cluster: worstCluster, Raw: scoreWorstNodeCap * worstFrac}})
}
