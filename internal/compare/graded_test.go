package compare

import (
	"fmt"
	"strings"
	"testing"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// TestRender_Graded verifies the score delta shows only when both sides are graded.
func TestRender_Graded(t *testing.T) {
	t.Parallel()
	tests := []struct {
		GradedA  bool
		GradedB  bool
		WantText string
		WantMD   string
	}{{ // Test 0: Both graded shows the delta.
		GradedA: true, GradedB: true, WantText: "(+10)", WantMD: "+10",
	}, { // Test 1: Ungraded before names that side.
		GradedB: true, WantText: "before not graded", WantMD: "before not graded",
	}, { // Test 2: Ungraded after names that side.
		GradedA: true, WantText: "after not graded", WantMD: "after not graded",
	}, { // Test 3: Neither graded says so.
		WantText: "neither scan graded", WantMD: "neither scan graded",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			a := &report.Report{FleetScore: report.FleetScore{Score: 70, Grade: "C", Graded: test.GradedA}}
			b := &report.Report{FleetScore: report.FleetScore{Score: 80, Grade: "B", Graded: test.GradedB}}
			d := Diff(a, b)
			if got := RenderText(d, false); !strings.Contains(got, test.WantText) {
				t.Errorf("text missing %q:\n%s", test.WantText, got)
			}
			if got := RenderMarkdown(d); !strings.Contains(got, test.WantMD) {
				t.Errorf("markdown missing %q:\n%s", test.WantMD, got)
			}
		})
	}
}
