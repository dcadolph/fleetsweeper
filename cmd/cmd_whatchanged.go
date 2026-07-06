package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// whatChangedCmd diffs two scans and prints what's new, what cleared,
// and how the per-cluster scores moved.
var whatChangedCmd = &cobra.Command{
	Use:   "whatchanged [scan-a] [scan-b]",
	Short: "Diff two scans: new findings, cleared findings, score deltas",
	Long: "Compares two scans and prints only what changed. When no IDs\n" +
		"are passed, the previous and current scans are compared. Useful\n" +
		"as a post-deploy gut check: ‘the score dropped — what new\n" +
		"finding showed up?’",
	Args: cobra.MaximumNArgs(2),
	RunE: runWhatChanged,
}

func init() {
	whatChangedCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable text.")
	whatChangedCmd.Flags().String("severity", "", "Only include findings at or above this severity (critical, warning, info). Empty includes all.")
}

// whatChangedDiff is the structured diff between two scans.
type whatChangedDiff struct {
	// ScanA is the older scan's ID.
	ScanA string `json:"scan_a"`
	// ScanB is the newer scan's ID.
	ScanB string `json:"scan_b"`
	// FleetScoreDelta is ScanB.FleetScore - ScanA.FleetScore.
	FleetScoreDelta int `json:"fleet_score_delta"`
	// FleetScoreA is the fleet score from the older scan.
	FleetScoreA int `json:"fleet_score_a"`
	// FleetScoreB is the fleet score from the newer scan.
	FleetScoreB int `json:"fleet_score_b"`
	// NewFindings are findings present in B but not in A.
	NewFindings []report.Finding `json:"new_findings,omitempty"`
	// ClearedFindings are findings present in A but not in B.
	ClearedFindings []report.Finding `json:"cleared_findings,omitempty"`
	// ClusterScoreChanges lists clusters whose score moved.
	ClusterScoreChanges []clusterScoreChange `json:"cluster_score_changes,omitempty"`
}

// clusterScoreChange records one cluster's score movement between scans.
type clusterScoreChange struct {
	// Cluster is the kubeconfig context name.
	Cluster string `json:"cluster"`
	// ScoreA is the score in the older scan.
	ScoreA int `json:"score_a"`
	// ScoreB is the score in the newer scan.
	ScoreB int `json:"score_b"`
	// Delta is ScoreB - ScoreA.
	Delta int `json:"delta"`
	// GradeA is the letter grade in the older scan.
	GradeA string `json:"grade_a"`
	// GradeB is the letter grade in the newer scan.
	GradeB string `json:"grade_b"`
}

// runWhatChanged implements the whatchanged subcommand.
func runWhatChanged(cmd *cobra.Command, args []string) error {
	st, err := openAnyStore(cmd)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := cmd.Context()
	scanA, scanB, err := resolveScans(ctx, st, args)
	if err != nil {
		return err
	}

	rptA, err := buildReport(ctx, st, scanA)
	if err != nil {
		return fmt.Errorf("build scan-a report: %w", err)
	}
	rptB, err := buildReport(ctx, st, scanB)
	if err != nil {
		return fmt.Errorf("build scan-b report: %w", err)
	}

	severity, _ := cmd.Flags().GetString("severity")
	diff := computeWhatChanged(rptA, rptB, scanA, scanB, severity)

	jsonOut, _ := cmd.Flags().GetBool("json")
	return writeWhatChanged(cmd.OutOrStdout(), diff, jsonOut)
}

// resolveScans returns the two scan IDs to diff. When args has two IDs
// they're used in (older, newer) order; the function does NOT reorder
// — the caller is in charge. With one arg, the second is "latest".
// With zero, it pairs the latest two scans.
func resolveScans(ctx context.Context, st store.Store, args []string) (string, string, error) {
	switch len(args) {
	case 2:
		return args[0], args[1], nil
	case 1:
		latest, err := latestScanID(ctx, st)
		if err != nil {
			return "", "", err
		}
		return args[0], latest, nil
	case 0:
		scans, err := st.ListScans(ctx, 2)
		if err != nil {
			return "", "", fmt.Errorf("list scans: %w", err)
		}
		if len(scans) < 2 {
			return "", "", fmt.Errorf("need at least 2 scans to diff; found %d", len(scans))
		}
		// ListScans returns newest first, so scans[1] is older.
		return scans[1].ID, scans[0].ID, nil
	}
	return "", "", fmt.Errorf("expected 0, 1, or 2 scan ids; got %d", len(args))
}

// latestScanID returns the most recent scan ID. Wraps the limit=1 call
// so resolveScans stays readable.
func latestScanID(ctx context.Context, st store.Store) (string, error) {
	scans, err := st.ListScans(ctx, 1)
	if err != nil {
		return "", fmt.Errorf("list scans: %w", err)
	}
	if len(scans) == 0 {
		return "", fmt.Errorf("no scans in store")
	}
	return scans[0].ID, nil
}

// buildReport rebuilds the report for one scan ID.
func buildReport(ctx context.Context, st store.Store, scanID string) (*report.Report, error) {
	scan, err := st.GetScan(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("get scan %s: %w", scanID, err)
	}
	results, err := st.GetScanResults(ctx, scanID)
	if err != nil {
		return nil, fmt.Errorf("get scan results %s: %w", scanID, err)
	}
	return report.Build(scan.Clusters, results), nil
}

// computeWhatChanged returns the structured diff. Findings are matched
// across reports by (cluster, scanner, title, severity) so a finding
// that re-fires on the same cluster with the same title doesn't appear
// as both new and cleared.
func computeWhatChanged(a, b *report.Report, idA, idB, minSeverity string) whatChangedDiff {
	diff := whatChangedDiff{
		ScanA:       idA,
		ScanB:       idB,
		FleetScoreA: a.FleetScore.Score,
		FleetScoreB: b.FleetScore.Score,
	}
	diff.FleetScoreDelta = diff.FleetScoreB - diff.FleetScoreA

	aSet := indexFindings(a.Findings, minSeverity)
	bSet := indexFindings(b.Findings, minSeverity)
	for k, f := range bSet {
		if _, present := aSet[k]; !present {
			diff.NewFindings = append(diff.NewFindings, f)
		}
	}
	for k, f := range aSet {
		if _, present := bSet[k]; !present {
			diff.ClearedFindings = append(diff.ClearedFindings, f)
		}
	}
	sortFindings(diff.NewFindings)
	sortFindings(diff.ClearedFindings)

	diff.ClusterScoreChanges = clusterScoreDelta(a, b)
	return diff
}

// indexFindings builds a key→finding map keyed on a tuple that is
// stable across scans for the "same" issue.
func indexFindings(in []report.Finding, minSeverity string) map[string]report.Finding {
	out := make(map[string]report.Finding, len(in))
	for _, f := range in {
		if !severityAtLeast(f.Severity, minSeverity) {
			continue
		}
		k := f.Cluster + "|" + f.Scanner + "|" + f.Severity + "|" + f.Title
		out[k] = f
	}
	return out
}

// severityAtLeast reports whether got is >= want in the
// critical>warning>info ordering. Empty want means "always pass."
func severityAtLeast(got, want string) bool {
	if want == "" {
		return true
	}
	rank := map[string]int{"info": 1, "warning": 2, "critical": 3}
	return rank[got] >= rank[want]
}

// sortFindings sorts in place: critical first, then by cluster, then title.
func sortFindings(f []report.Finding) {
	sevRank := map[string]int{"critical": 0, "warning": 1, "info": 2}
	sort.SliceStable(f, func(i, j int) bool {
		ri, rj := sevRank[f[i].Severity], sevRank[f[j].Severity]
		if ri != rj {
			return ri < rj
		}
		if f[i].Cluster != f[j].Cluster {
			return f[i].Cluster < f[j].Cluster
		}
		return f[i].Title < f[j].Title
	})
}

// clusterScoreDelta returns one record per cluster whose score moved.
// Clusters that appear in only one scan are skipped.
func clusterScoreDelta(a, b *report.Report) []clusterScoreChange {
	scoresA := indexClusterScores(a)
	scoresB := indexClusterScores(b)
	var out []clusterScoreChange
	for cluster, scoreA := range scoresA {
		scoreB, ok := scoresB[cluster]
		if !ok {
			continue
		}
		if scoreA.Score == scoreB.Score {
			continue
		}
		out = append(out, clusterScoreChange{
			Cluster: cluster,
			ScoreA:  scoreA.Score,
			ScoreB:  scoreB.Score,
			Delta:   scoreB.Score - scoreA.Score,
			GradeA:  scoreA.Grade,
			GradeB:  scoreB.Grade,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		// Biggest regression first (most negative delta).
		return out[i].Delta < out[j].Delta
	})
	return out
}

// indexClusterScores maps cluster name to its computed score for one scan.
func indexClusterScores(r *report.Report) map[string]report.ClusterScore {
	out := map[string]report.ClusterScore{}
	for _, cs := range report.ComputeClusterScores(r) {
		out[cs.Cluster] = cs
	}
	return out
}

// writeWhatChanged renders diff to w in the chosen format.
func writeWhatChanged(w io.Writer, diff whatChangedDiff, jsonOut bool) error {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(diff)
	}
	fmt.Fprintf(w, "Comparing %s -> %s\n", diff.ScanA, diff.ScanB)
	fmt.Fprintf(w, "Fleet score: %d -> %d (%+d)\n",
		diff.FleetScoreA, diff.FleetScoreB, diff.FleetScoreDelta)
	fmt.Fprintln(w)

	renderFindingsBlock(w, "New findings", diff.NewFindings)
	renderFindingsBlock(w, "Cleared findings", diff.ClearedFindings)

	if len(diff.ClusterScoreChanges) > 0 {
		fmt.Fprintln(w, "Cluster score changes:")
		for _, c := range diff.ClusterScoreChanges {
			fmt.Fprintf(w, "  %-30s  %3d (%s) -> %3d (%s)  %+d\n",
				c.Cluster, c.ScoreA, c.GradeA, c.ScoreB, c.GradeB, c.Delta)
		}
	} else {
		fmt.Fprintln(w, "Cluster scores: no changes.")
	}
	return nil
}

// renderFindingsBlock prints a labeled list of findings, or "(none)".
func renderFindingsBlock(w io.Writer, label string, findings []report.Finding) {
	fmt.Fprintf(w, "%s (%d):\n", label, len(findings))
	if len(findings) == 0 {
		fmt.Fprintln(w, "  (none)")
		fmt.Fprintln(w)
		return
	}
	for _, f := range findings {
		title := f.Title
		if title == "" {
			title = "(untitled)"
		}
		fmt.Fprintf(w, "  [%s] %s — %s\n", strings.ToUpper(f.Severity), f.Cluster, title)
	}
	fmt.Fprintln(w)
}
