package report

import (
	"strings"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

// observation says whether a scanner field was measured on a cluster. The zero value is
// unobserved, so a lookup that fails for any reason never reads as a measurement.
type observation int

const (
	// unobserved means no scanner measured the value: the run errored, never ran on the
	// cluster, or did not emit the field.
	unobserved observation = iota
	// partial means the field is present but the run was degraded, so other reads in the
	// same run failed.
	partial
	// observed means the field is present and the run completed, or the run found the
	// scanned feature not served, which is a trustworthy "nothing here".
	observed
)

// partialScanNote is appended to a finding's description when it rests on a degraded run.
const partialScanNote = " (partial scan)"

// runKey identifies one scanner run on one cluster.
type runKey struct {
	// scanner is the scanner name.
	scanner string
	// cluster is the cluster name.
	cluster string
}

// indexRuns derives every run's state from r.Degraded and the section payloads. A run listed
// in Degraded carries that state, a run with a payload and no Degraded entry is OK, and a run
// with neither is absent from the map. A report decoded from JSON yields the same table, so
// the accessor needs nothing restored after a load.
func indexRuns(r *Report) map[runKey]scanner.State {
	runs := make(map[runKey]scanner.State)
	for name, sec := range r.Sections {
		if sec == nil {
			continue
		}
		for cluster := range sec.PerCluster {
			runs[runKey{scanner: name, cluster: cluster}] = scanner.StateOK
		}
	}
	for _, d := range r.Degraded {
		runs[runKey{scanner: d.Scanner, cluster: d.Cluster}] = scanner.State(d.State)
	}
	return runs
}

// runState returns the state of scannerName's run on cluster and whether the run exists. It
// reads the table Build fills and derives the state from the report when the table is absent.
func runState(r *Report, scannerName, cluster string) (scanner.State, bool) {
	runs := r.runs
	if runs == nil {
		runs = indexRuns(r)
	}
	st, ok := runs[runKey{scanner: scannerName, cluster: cluster}]
	return st, ok
}

// clusterView returns a cluster's scanner payload as a generic map and how far it can be
// trusted. An errored or absent run, or a payload that does not convert, is unobserved with a
// nil map. The map may be the report's own, so callers must not modify it.
func clusterView(r *Report, scannerName, cluster string) (map[string]any, observation) {
	st, ok := runState(r, scannerName, cluster)
	if !ok || st == scanner.StateErrored {
		return nil, unobserved
	}
	sec := r.Sections[scannerName]
	if sec == nil {
		return nil, unobserved
	}
	data, ok := sec.PerCluster[cluster]
	if !ok {
		return nil, unobserved
	}
	m, _ := genericMap(data)
	if m == nil {
		return nil, unobserved
	}
	if st == scanner.StateDegraded {
		return m, partial
	}
	return m, observed
}

// observe returns a numeric field from a cluster's scanner payload and its observation. A
// missing or non-numeric field is unobserved with a zero value the caller must not use.
func observe(r *Report, scannerName, cluster, field string) (float64, observation) {
	m, obs := clusterView(r, scannerName, cluster)
	if obs == unobserved {
		return 0, unobserved
	}
	v, ok := util.Float64(m[field])
	if !ok {
		return 0, unobserved
	}
	return v, obs
}

// observeInt returns observe's value truncated to an int.
func observeInt(r *Report, scannerName, cluster, field string) (int, observation) {
	v, obs := observe(r, scannerName, cluster, field)
	return int(v), obs
}

// observeString returns a string field from a cluster's scanner payload and its observation.
// A missing or non-string field is unobserved.
func observeString(r *Report, scannerName, cluster, field string) (string, observation) {
	m, obs := clusterView(r, scannerName, cluster)
	if obs == unobserved {
		return "", unobserved
	}
	s, ok := m[field].(string)
	if !ok {
		return "", unobserved
	}
	return s, obs
}

// seen reports whether obs carries a value, observed or partial. Presence rules use it.
func (obs observation) seen() bool {
	return obs != unobserved
}

// note returns the description suffix for a finding resting on obs.
func (obs observation) note() string {
	if obs == partial {
		return partialScanNote
	}
	return ""
}

// runNote returns the description suffix for a finding resting on scannerName's run on
// cluster: the partial-scan note when the run was degraded, and "" otherwise.
func runNote(r *Report, scannerName, cluster string) string {
	if st, _ := runState(r, scannerName, cluster); st == scanner.StateDegraded {
		return partialScanNote
	}
	return ""
}

// appendSentence appends sentence to desc and keeps the partial-scan note last. The note ends
// the result when desc already ended with it or partial is set.
func appendSentence(desc, sentence string, partial bool) string {
	base, noted := strings.CutSuffix(desc, partialScanNote)
	out := strings.TrimSpace(base + " " + sentence)
	if noted || partial {
		out += partialScanNote
	}
	return out
}

// weakest returns the least trustworthy of obs, so a finding resting on several fields
// reports the weakest of them.
func weakest(obs ...observation) observation {
	out := observed
	for _, o := range obs {
		out = min(out, o)
	}
	return out
}
