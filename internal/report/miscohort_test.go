package report

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/dcadolph/fleetsweeper/internal/cohort"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

// misCohortShape names a synthetic scanner profile used by mis-cohort fixtures.
type misCohortShape int

const (
	shapeProd misCohortShape = iota
	shapeDev
)

// misCohortResults builds scanner results for each cluster in shapes.
func misCohortResults(shapes map[string]misCohortShape) map[string]map[string]scanner.Result {
	prod := map[string]map[string]any{
		"resources":  {"node_count": 12.0},
		"metrics":    {"avg_cpu_percent": 60.0, "avg_memory_percent": 65.0},
		"namespaces": {"count": 14.0},
	}
	dev := map[string]map[string]any{
		"resources":  {"node_count": 2.0},
		"metrics":    {"avg_cpu_percent": 15.0, "avg_memory_percent": 22.0},
		"namespaces": {"count": 4.0},
	}
	out := map[string]map[string]scanner.Result{}
	for c, shape := range shapes {
		data := prod
		if shape == shapeDev {
			data = dev
		}
		res := map[string]scanner.Result{}
		for name, d := range data {
			res[name] = scanner.Result{Scanner: name, Data: d}
		}
		out[c] = res
	}
	return out
}

// misCohortFleet builds a report and tag map from ordered clusters. Each cluster
// is tagged with the matching entry in tags.
func misCohortFleet(
	names []string, shapes map[string]misCohortShape, tags map[string]string,
) (*Report, map[string]string) {
	rpt := Build(names, misCohortResults(shapes), BuildOptions{ClusterTags: tags})
	return rpt, tags
}

// oopsFleet is the standard fleet: four prod, four dev, and one dev-shaped
// cluster tagged prod.
func oopsFleet() ([]string, map[string]misCohortShape, map[string]string) {
	names := []string{"p1", "p2", "p3", "p4", "d1", "d2", "d3", "d4", "oops"}
	shapes := map[string]misCohortShape{"oops": shapeDev}
	tags := map[string]string{"oops": "prod"}
	for _, n := range names[:4] {
		shapes[n] = shapeProd
		tags[n] = "prod"
	}
	for _, n := range names[4:8] {
		shapes[n] = shapeDev
		tags[n] = "dev"
	}
	return names, shapes, tags
}

// TestDetectMisCohort verifies the exact findings for each fleet shape.
func TestDetectMisCohort(t *testing.T) {
	t.Parallel()

	oopsNames, oopsShapes, oopsTags := oopsFleet()

	smallNames := oopsNames[:7]
	smallTags := map[string]string{}
	for _, n := range smallNames {
		smallTags[n] = oopsTags[n]
	}

	lowPopTags := map[string]string{
		"p1": "prod", "p2": "prod", "p3": "stage", "p4": "stage",
		"d1": "dev", "d2": "dev", "d3": "qa", "d4": "qa", "oops": "solo",
	}

	tieNames := []string{
		"p1", "p2", "p3", "p4", "a1", "a2", "a3", "z1", "z2", "z3", "x",
	}
	tieShapes := map[string]misCohortShape{"x": shapeDev}
	tieTags := map[string]string{"x": "prod"}
	for _, n := range tieNames[:4] {
		tieShapes[n] = shapeProd
		tieTags[n] = "prod"
	}
	for _, n := range tieNames[4:7] {
		tieShapes[n] = shapeDev
		tieTags[n] = "zeta"
	}
	for _, n := range tieNames[7:10] {
		tieShapes[n] = shapeDev
		tieTags[n] = "alpha"
	}

	tests := []struct {
		Names     []string
		Shapes    map[string]misCohortShape
		Tags      map[string]string
		WantFinds []MisCohortFinding
	}{
		{ // Test 0: Fleet under the minimum size gives none.
			Names: smallNames, Shapes: oopsShapes, Tags: smallTags,
		},
		{ // Test 1: Empty tags gives none.
			Names: oopsNames, Shapes: oopsShapes, Tags: map[string]string{},
		},
		{ // Test 2: Tags below the minimum population give none.
			Names: oopsNames, Shapes: oopsShapes, Tags: lowPopTags,
		},
		{ // Test 3: The oops cluster is flagged with the dev profile match.
			Names: oopsNames, Shapes: oopsShapes, Tags: oopsTags,
			WantFinds: []MisCohortFinding{
				{Cluster: "oops", TaggedAs: "prod", ProfileMatches: "dev"},
			},
		},
		{ // Test 4: Two tags sharing a dominant cohort give the first alphabetically.
			Names: tieNames, Shapes: tieShapes, Tags: tieTags,
			WantFinds: []MisCohortFinding{
				{Cluster: "x", TaggedAs: "prod", ProfileMatches: "alpha"},
			},
		},
	}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			rpt, tags := misCohortFleet(test.Names, test.Shapes, test.Tags)
			got := detectMisCohort(rpt, tags)
			if diff := cmp.Diff(test.WantFinds, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestMisCohortFindings verifies both Description templates of the converted findings.
func TestMisCohortFindings(t *testing.T) {
	t.Parallel()

	names, shapes, tags := oopsFleet()
	rpt, _ := misCohortFleet(names, shapes, tags)
	got := misCohortFindings(rpt, tags)
	wantDesc := `Cluster "oops" is tagged ` + "%s" +
		`="prod", but its scanner profile clusters with the "dev" population.`
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if want := fmt.Sprintf(wantDesc, cohort.DefaultTagKey); got[0].Description != want {
		t.Errorf("description = %q, want %q", got[0].Description, want)
	}

	// With no matching tag the second template is used.
	noMatch := map[string]string{}
	for k, v := range tags {
		noMatch[k] = v
	}
	for _, n := range []string{"d1", "d2", "d3", "d4"} {
		delete(noMatch, n)
	}
	got = misCohortFindings(rpt, noMatch)
	if len(got) != 1 {
		t.Fatalf("no-match: got %d findings, want 1", len(got))
	}
	want := fmt.Sprintf(
		`Cluster "oops" is tagged %s="prod", but its scanner profile does not match `+
			`the rest of the "prod" cohort.`, cohort.DefaultTagKey)
	if got[0].Description != want {
		t.Errorf("description = %q, want %q", got[0].Description, want)
	}
}

// TestBuildFindingsSorted verifies Build orders findings by severity across all sources.
func TestBuildFindingsSorted(t *testing.T) {
	t.Parallel()

	tests := []struct {
		WantInfo     bool
		WantMisCount int
	}{{ // Test 0: Mis-cohort warning sorts ahead of info findings from other sources.
		WantInfo: true, WantMisCount: 1,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			names, shapes, tags := oopsFleet()
			rpt, _ := misCohortFleet(names, shapes, tags)
			var gotInfo bool
			var gotMis int
			for i, f := range rpt.Findings {
				gotInfo = gotInfo || f.Severity == SeverityInfo
				if f.Rule == "cohort/wrong-cohort" {
					gotMis++
				}
				if i > 0 && util.SeverityRank(rpt.Findings[i-1].Severity) <
					util.SeverityRank(f.Severity) {
					t.Errorf("finding %d (%s) is less severe than the one before it", i, f.Rule)
				}
			}
			if diff := cmp.Diff(test.WantInfo, gotInfo); diff != "" {
				t.Errorf("info presence mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantMisCount, gotMis, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("mis-cohort count mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
