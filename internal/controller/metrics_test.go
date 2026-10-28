package controller

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestWriteMetrics verifies the exact sample lines for every series. It is not parallel
// because the counters are package globals.
func TestWriteMetrics(t *testing.T) {
	ResetMetrics()
	t.Cleanup(ResetMetrics)

	calls := []struct {
		Record func()
		Count  int
	}{
		{recordReconcile, 7},
		{recordReconcileOK, 3},
		{recordReconcileFail, 2},
		{recordScanTriggered, 5},
		{func() { recordScanResult(true) }, 4},
		{func() { recordScanResult(false) }, 1},
		{recordPaused, 6},
	}
	for _, c := range calls {
		for range c.Count {
			c.Record()
		}
	}

	var sb strings.Builder
	WriteMetrics(&sb)

	var got []string
	for _, line := range strings.Split(strings.TrimSpace(sb.String()), "\n") {
		if line != "" && !strings.HasPrefix(line, "#") {
			got = append(got, line)
		}
	}

	want := []string{
		`fleetsweeper_controller_reconcile_total 7`,
		`fleetsweeper_controller_reconcile_outcome_total{outcome="success"} 3`,
		`fleetsweeper_controller_reconcile_outcome_total{outcome="failure"} 2`,
		`fleetsweeper_controller_scans_total{result="triggered"} 5`,
		`fleetsweeper_controller_scans_total{result="success"} 4`,
		`fleetsweeper_controller_scans_total{result="failure"} 1`,
		`fleetsweeper_controller_paused_resources 6`,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("sample lines mismatch (-want +got):\n%s", diff)
	}
	if !strings.Contains(sb.String(), "# HELP fleetsweeper_controller_paused_resources "+
		"Reconcile passes that found spec.paused=true.\n") {
		t.Errorf("paused HELP text missing:\n%s", sb.String())
	}
}
