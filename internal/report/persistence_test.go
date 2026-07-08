package report

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/util"
)

func TestComputePersistence(t *testing.T) {
	t.Parallel()

	fA := Finding{Title: "a", Severity: SeverityCritical, Cluster: "c1", Scanner: "s1"}
	fB := Finding{Title: "b", Severity: SeverityWarning, Cluster: "c2", Scanner: "s2"}
	fC := Finding{Title: "c", Severity: SeverityInfo, Cluster: "c3", Scanner: "s3"}
	fD := Finding{Title: "d", Severity: SeverityWarning, Cluster: "c4", Scanner: "s4"}

	fp := func(f Finding) string { return util.Fingerprint(f.Cluster, f.Scanner, f.Title) }

	tests := []struct {
		Acked      map[string]bool
		In         [][]Finding
		WantResult []FindingPersistence
	}{
		{ // Test 0: Empty series yields no results.
			In:         nil,
			WantResult: nil,
		},
		{ // Test 1: Single scan, every finding is chronic at full recurrence.
			In: [][]Finding{{fA, fB}},
			WantResult: []FindingPersistence{
				{Fingerprint: fp(fA), Cluster: "c1", Scanner: "s1", Title: "a", Severity: SeverityCritical, Present: 1, Total: 1, Fraction: 1, Streak: 1, Class: PersistenceChronic},
				{Fingerprint: fp(fB), Cluster: "c2", Scanner: "s2", Title: "b", Severity: SeverityWarning, Present: 1, Total: 1, Fraction: 1, Streak: 1, Class: PersistenceChronic},
			},
		},
		{ // Test 2: Four scans mix chronic, intermittent, and transient; acks flagged; a duplicate within one scan counts once.
			Acked: map[string]bool{fp(fB): true},
			In: [][]Finding{
				{fA, fD},
				{fA, fB},
				{fA, fB},
				{fA, fA, fB, fC, fD},
			},
			WantResult: []FindingPersistence{
				{Fingerprint: fp(fA), Cluster: "c1", Scanner: "s1", Title: "a", Severity: SeverityCritical, Present: 4, Total: 4, Fraction: 1, Streak: 4, Class: PersistenceChronic},
				{Fingerprint: fp(fB), Cluster: "c2", Scanner: "s2", Title: "b", Severity: SeverityWarning, Present: 3, Total: 4, Fraction: 0.75, Streak: 3, Class: PersistenceChronic, Acked: true},
				{Fingerprint: fp(fD), Cluster: "c4", Scanner: "s4", Title: "d", Severity: SeverityWarning, Present: 2, Total: 4, Fraction: 0.5, Streak: 1, Class: PersistenceIntermittent},
				{Fingerprint: fp(fC), Cluster: "c3", Scanner: "s3", Title: "c", Severity: SeverityInfo, Present: 1, Total: 4, Fraction: 0.25, Streak: 1, Class: PersistenceTransient},
			},
		},
	}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := ComputePersistence(test.In, test.Acked)
			if diff := cmp.Diff(test.WantResult, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
