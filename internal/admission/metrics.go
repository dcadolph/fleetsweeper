package admission

import (
	"fmt"
	"io"
	"sort"
	"sync"
	"sync/atomic"
)

// Decision labels recorded in fleetsweeper_admission_decisions_total.
const (
	// DecisionAllowed is a pod evaluated and allowed with no warnings.
	DecisionAllowed = "allowed"
	// DecisionDenied is a pod evaluated and denied.
	DecisionDenied = "denied"
	// DecisionWarned is a pod evaluated and allowed with at least one warning.
	DecisionWarned = "warned"
	// DecisionSkipped is a request that was not evaluated.
	DecisionSkipped = "skipped"
)

var (
	// decisionNames lists the decision labels in output order.
	decisionNames = []string{DecisionAllowed, DecisionDenied, DecisionWarned, DecisionSkipped}
	// modeNames lists the mode labels in output order.
	modeNames = []string{string(ModeAdvisory), string(ModeEnforce)}
)

// Metrics holds the webhook counters. The zero value is ready to use and safe for concurrent
// use. A nil *Metrics ignores every record call.
type Metrics struct {
	// decisions counts decisions indexed by mode then decision.
	decisions [2][4]atomic.Int64
	// failures counts checks that fired, keyed by check name to *atomic.Int64.
	failures sync.Map
}

// RecordDecision counts one admission decision under the given mode.
func (m *Metrics) RecordDecision(mode Mode, decision string) {
	if m == nil {
		return
	}
	mi := 0
	if mode.enforcing() {
		mi = 1
	}
	for di, name := range decisionNames {
		if name == decision {
			m.decisions[mi][di].Add(1)
			return
		}
	}
}

// RecordCheckFailure counts one pod that fired the named check.
func (m *Metrics) RecordCheckFailure(check string) {
	if m == nil {
		return
	}
	c, _ := m.failures.LoadOrStore(check, new(atomic.Int64))
	c.(*atomic.Int64).Add(1)
}

// WriteTo emits the counters in Prometheus text exposition format. It implements io.WriterTo.
func (m *Metrics) WriteTo(w io.Writer) (int64, error) {
	if m == nil {
		return 0, nil
	}
	var total int64
	var werr error
	line := func(s string) {
		if werr != nil {
			return
		}
		n, err := io.WriteString(w, s+"\n")
		total += int64(n)
		werr = err
	}
	line("# HELP fleetsweeper_admission_decisions_total Admission decisions since startup, by mode and decision.")
	line("# TYPE fleetsweeper_admission_decisions_total counter")
	for mi, mode := range modeNames {
		for di, decision := range decisionNames {
			line(fmt.Sprintf(`fleetsweeper_admission_decisions_total{mode=%q,decision=%q} %d`,
				mode, decision, m.decisions[mi][di].Load()))
		}
	}
	line("# HELP fleetsweeper_admission_check_failures_total Pods that fired a fleet-norm check since startup, by check.")
	line("# TYPE fleetsweeper_admission_check_failures_total counter")
	var names []string
	counts := map[string]int64{}
	m.failures.Range(func(k, v any) bool {
		name := k.(string)
		names = append(names, name)
		counts[name] = v.(*atomic.Int64).Load()
		return true
	})
	sort.Strings(names)
	for _, name := range names {
		line(fmt.Sprintf(`fleetsweeper_admission_check_failures_total{check=%q} %d`, name, counts[name]))
	}
	return total, werr
}
