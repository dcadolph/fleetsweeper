package report

import (
	"fmt"
	"sort"
)

// Incident groups findings that share a likely root cause on one cluster, so an
// operator reads one incident instead of a flat list of symptoms. A failing
// admission webhook, an expiring cert, and a deprecated-API rejection are one
// incident, not three unrelated warnings.
type Incident struct {
	// Cluster is the cluster the incident is on.
	Cluster string `json:"cluster"`
	// Title is a synthesized one-line summary.
	Title string `json:"title"`
	// Theme is the root-cause family the fused findings belong to.
	Theme string `json:"theme"`
	// Severity is the highest severity among the member findings.
	Severity string `json:"severity"`
	// Summary is a deterministic, templated root-cause hypothesis.
	Summary string `json:"summary"`
	// Findings lists the titles of the fused member findings, sorted.
	Findings []string `json:"findings"`
}

// incidentThemes maps a scanner to the root-cause family its findings belong to.
// Findings whose scanners share a theme on the same cluster fuse into one
// incident.
var incidentThemes = map[string]string{
	"admission":         "admission-control",
	"certs":             "admission-control",
	"deprecated-apis":   "admission-control",
	"node-health":       "node-pressure",
	"metrics":           "node-pressure",
	"events":            "node-pressure",
	"workload-security": "security-posture",
	"rbac-audit":        "security-posture",
	"security":          "security-posture",
	"network-policies":  "security-posture",
	"image-audit":       "security-posture",
}

// incidentTitles gives each theme a short human label for the incident title.
var incidentTitles = map[string]string{
	"admission-control": "admission path degraded",
	"node-pressure":     "resource exhaustion",
	"security-posture":  "security posture gaps",
}

// incidentSummaries gives each theme a deterministic root-cause hypothesis.
var incidentSummaries = map[string]string{
	"admission-control": "Certificate, webhook, and deprecated-API problems overlap on this cluster and point at a failing admission path. A broken admission webhook can cascade into rejected or unvalidated workloads.",
	"node-pressure":     "Node pressure, elevated utilization, and a warning-event spike overlap on this cluster and point at resource exhaustion. Pods risk eviction and OOM kills.",
	"security-posture":  "Workload-security, RBAC, network-policy, and image gaps overlap on this cluster and widen its attack surface at the same time.",
}

// FuseIncidents groups findings by cluster and root-cause theme, emitting an
// incident wherever two or more findings on a cluster share a theme. Findings
// with no theme, or that stand alone, are left as ordinary findings.
func FuseIncidents(findings []Finding) []Incident {
	type key struct{ cluster, theme string }
	groups := make(map[key][]Finding)
	for _, f := range findings {
		theme, ok := incidentThemes[f.Scanner]
		if !ok || f.Cluster == "" || f.Cluster == "fleet" {
			continue
		}
		k := key{f.Cluster, theme}
		groups[k] = append(groups[k], f)
	}

	var incidents []Incident
	for k, fs := range groups {
		if len(fs) < 2 {
			continue
		}
		titles := make([]string, len(fs))
		for i, f := range fs {
			titles[i] = f.Title
		}
		sort.Strings(titles)
		incidents = append(incidents, Incident{
			Cluster:  k.cluster,
			Title:    fmt.Sprintf("%s: %s (%d signals)", k.cluster, incidentTitles[k.theme], len(fs)),
			Theme:    k.theme,
			Severity: maxSeverityOf(fs),
			Summary:  incidentSummaries[k.theme],
			Findings: titles,
		})
	}

	sort.Slice(incidents, func(i, j int) bool {
		if si, sj := sevRank(incidents[i].Severity), sevRank(incidents[j].Severity); si != sj {
			return si < sj
		}
		if incidents[i].Cluster != incidents[j].Cluster {
			return incidents[i].Cluster < incidents[j].Cluster
		}
		return incidents[i].Theme < incidents[j].Theme
	})
	return incidents
}

// sevRank orders severities so critical sorts ahead of warning ahead of info.
func sevRank(s string) int {
	switch s {
	case SeverityCritical:
		return 0
	case SeverityWarning:
		return 1
	default:
		return 2
	}
}

// maxSeverityOf returns the highest severity among the given findings.
func maxSeverityOf(fs []Finding) string {
	best := SeverityInfo
	for _, f := range fs {
		if sevRank(f.Severity) < sevRank(best) {
			best = f.Severity
		}
	}
	return best
}
