package report

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// stepScans builds n scans of a 10-cluster fleet on security/enforced_count.
// Every cluster holds steady, except c04, which steps from 24 to 80 at scan
// step (0-based) and stays there.
func stepScans(n, step int) []ScanReport {
	base := []float64{20, 22, 23, 24, 24, 25, 26, 26, 28, 30}
	scans := make([]ScanReport, 0, n)
	for s := range n {
		clusters := make([]string, 0, len(base))
		results := make(map[string]map[string]scanner.Result, len(base))
		for i, v := range base {
			c := fmt.Sprintf("c%02d", i)
			if c == "c04" && s >= step {
				v = 80
			}
			clusters = append(clusters, c)
			results[c] = map[string]scanner.Result{
				"security": {Scanner: "security", Data: map[string]any{"enforced_count": v}},
			}
		}
		scans = append(scans, ScanReport{ID: fmt.Sprintf("scan-%d", s+1), Report: Build(clusters, results)})
	}
	return scans
}

// TestDriftLedgerStep verifies a cluster whose value steps between the third
// and fourth scan leads the ledger, with the flag it gained stamped with the
// fourth scan.
func TestDriftLedgerStep(t *testing.T) {
	t.Parallel()
	l := DriftLedger(stepScans(6, 3))

	if diff := cmp.Diff([]string{"scan-1", "scan-2", "scan-3", "scan-4", "scan-5", "scan-6"}, l.Scans); diff != "" {
		t.Errorf("scans mismatch (-want +got):\n%s", diff)
	}
	if len(l.Clusters) == 0 {
		t.Fatal("ledger is empty")
	}
	top := l.Clusters[0]
	if top.Cluster != "c04" {
		t.Fatalf("first row is %s, want c04; ledger %+v", top.Cluster, l.Clusters)
	}
	wantGained := []FlagChange{{Scanner: "security", Field: "enforced_count", Scan: "scan-4"}}
	if diff := cmp.Diff(wantGained, top.Gained); diff != "" {
		t.Errorf("gained mismatch (-want +got):\n%s", diff)
	}
	if len(top.Lost) != 0 {
		t.Errorf("lost: want none, got %v", top.Lost)
	}
	if top.MassBefore != top.Mass[0] || top.MassAfter != top.Mass[5] || top.MassDelta <= 0 {
		t.Errorf("mass: before %v after %v delta %v, series %v", top.MassBefore, top.MassAfter, top.MassDelta, top.Mass)
	}
	if top.Mass[2] != top.Mass[0] || top.Mass[3] == top.Mass[2] {
		t.Errorf("mass series should hold through scan 3 and move at scan 4: %v", top.Mass)
	}
	if len(top.Fields) == 0 || top.Fields[0].Field != "enforced_count" || top.Fields[0].Before != "24" || top.Fields[0].After != "80" {
		t.Errorf("moved fields: want enforced_count 24 -> 80 first, got %+v", top.Fields)
	}
}

// TestDriftLedgerLostFlag verifies a cluster that returns to the norm reports
// the flag it lost and the scan it recovered in.
func TestDriftLedgerLostFlag(t *testing.T) {
	t.Parallel()
	scans := stepScans(4, 0)
	recovered := stepScans(4, 10)
	scans[2], scans[3] = recovered[2], recovered[3]
	scans[2].ID, scans[3].ID = "scan-3", "scan-4"

	l := DriftLedger(scans)
	if len(l.Clusters) == 0 || l.Clusters[0].Cluster != "c04" {
		t.Fatalf("want c04 first, got %+v", l.Clusters)
	}
	want := []FlagChange{{Scanner: "security", Field: "enforced_count", Scan: "scan-3"}}
	if diff := cmp.Diff(want, l.Clusters[0].Lost); diff != "" {
		t.Errorf("lost mismatch (-want +got):\n%s", diff)
	}
}

// TestDriftLedgerSteady verifies scans with nothing moving give an empty
// ledger, and fewer than two scans give one with no rows.
func TestDriftLedgerSteady(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Scans     []ScanReport
		WantScans int
	}{{ // Test 0: Three identical scans.
		Scans: stepScans(3, 10), WantScans: 3,
	}, { // Test 1: One scan.
		Scans: stepScans(1, 10), WantScans: 1,
	}, { // Test 2: No scans.
		Scans: nil, WantScans: 0,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			l := DriftLedger(test.Scans)
			if len(l.Scans) != test.WantScans {
				t.Errorf("scans: want %d, got %d", test.WantScans, len(l.Scans))
			}
			if diff := cmp.Diff([]ClusterDrift{}, l.Clusters, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("rows mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestDriftLedgerIgnoresNormOnlyMoves verifies clusters whose values hold
// while the norm moves under them get no row, even though their z changed.
func TestDriftLedgerIgnoresNormOnlyMoves(t *testing.T) {
	t.Parallel()
	l := DriftLedger(stepScans(6, 3))
	names := make([]string, 0, len(l.Clusters))
	for _, c := range l.Clusters {
		names = append(names, c.Cluster)
	}
	if diff := cmp.Diff([]string{"c04"}, names); diff != "" {
		t.Errorf("rows mismatch (-want +got):\n%s", diff)
	}
}

// TestDriftLedgerFlapping verifies a flag that flips on, off, and on again is
// stamped with the scan of its last flip, not its first.
func TestDriftLedgerFlapping(t *testing.T) {
	t.Parallel()
	steady, stepped := stepScans(5, 10), stepScans(5, 0)
	scans := []ScanReport{steady[0], stepped[1], steady[2], stepped[3], stepped[4]}
	for i := range scans {
		scans[i].ID = fmt.Sprintf("scan-%d", i+1)
	}
	l := DriftLedger(scans)
	if len(l.Clusters) == 0 || l.Clusters[0].Cluster != "c04" {
		t.Fatalf("want c04 first, got %+v", l.Clusters)
	}
	want := []FlagChange{{Scanner: "security", Field: "enforced_count", Scan: "scan-4"}}
	if diff := cmp.Diff(want, l.Clusters[0].Gained); diff != "" {
		t.Errorf("gained mismatch (-want +got):\n%s", diff)
	}
}
