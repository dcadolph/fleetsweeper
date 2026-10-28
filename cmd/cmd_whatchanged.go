package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/compare"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

// maxDriftScans caps how many scans the whatchanged drift ledger reads. A wider
// window keeps scan-a and the most recent scans up to the cap.
const maxDriftScans = 50

// maxDriftLines is how many drifted clusters whatchanged lists.
const maxDriftLines = 10

// whatChangedCmd diffs two scans and prints what's new, what cleared,
// and how the per-cluster scores moved.
var whatChangedCmd = &cobra.Command{
	Use:   "whatchanged [scan-a] [scan-b]",
	Short: "Diff two scans: drifted clusters, new and cleared findings, score deltas.",
	Example: "  fleetsweeper whatchanged --db fleet.db\n" +
		"  fleetsweeper whatchanged 41 42 --db fleet.db --severity warning",
	Long: "Compares two scans and prints only what changed. When no IDs\n" +
		"are passed, the previous and current scans are compared. The drift\n" +
		"ledger reads every stored scan between the two, so each outlier flag\n" +
		"a cluster gained or lost names the scan it flipped in. Useful as a\n" +
		"post-deploy gut check: the score dropped, so what moved?",
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
	// Drift is the drift ledger over every stored scan from A to B.
	Drift report.Ledger `json:"drift"`
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
	severity, _ := cmd.Flags().GetString("severity")
	if err := oneOf("severity", severity, "", "critical", "warning", "info"); err != nil {
		return err
	}
	st, err := openAnyStore(cmd)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := cmdContext(cmd)
	scanA, scanB, err := resolveScans(ctx, st, args)
	if err != nil {
		return err
	}

	rptA, _, err := loadStoredReport(ctx, st, scanA)
	if err != nil {
		return fmt.Errorf("build scan-a report: %w", err)
	}
	rptB, _, err := loadStoredReport(ctx, st, scanB)
	if err != nil {
		return fmt.Errorf("build scan-b report: %w", err)
	}

	diff := computeWhatChanged(rptA, rptB, scanA, scanB, severity)
	window, err := driftWindow(ctx, st, scanA, scanB, rptA, rptB)
	if err != nil {
		return err
	}
	diff.Drift = report.DriftLedger(window)

	jsonOut, _ := cmd.Flags().GetBool("json")
	return writeWhatChanged(cmd.OutOrStdout(), diff, jsonOut)
}

// resolveScans returns the two scan IDs to diff, in the order given: the caller is in charge of
// putting the older scan first. With one ref the second is latest. With none it pairs the
// previous and latest scans.
func resolveScans(ctx context.Context, st store.Store, args []string) (string, string, error) {
	var refs [2]string
	switch len(args) {
	case 2:
		refs = [2]string{args[0], args[1]}
	case 1:
		refs = [2]string{args[0], "latest"}
	case 0:
		refs = [2]string{"previous", "latest"}
	default:
		return "", "", fmt.Errorf("expected 0, 1, or 2 scan ids; got %d", len(args))
	}
	a, err := resolveScanRef(ctx, st, refs[0])
	if err != nil {
		return "", "", err
	}
	b, err := resolveScanRef(ctx, st, refs[1])
	if err != nil {
		return "", "", err
	}
	return a, b, nil
}

// driftWindow returns the scans from scanA to scanB, oldest first, with the
// reports already built for the two ends reused. Scans stored between them are
// read so a flag flip is stamped with the scan it happened in. When scanA is
// not older than scanB the window is just the two. A window wider than
// maxDriftScans keeps scanA and the newest scans up to the cap.
func driftWindow(ctx context.Context, st store.Store, scanA, scanB string, rptA, rptB *report.Report) ([]report.ScanReport, error) {
	ends := []report.ScanReport{{ID: scanA, Report: rptA}, {ID: scanB, Report: rptB}}
	a, err := st.GetScan(ctx, scanA)
	if err != nil {
		return nil, fmt.Errorf("get scan %s: %w", scanA, err)
	}
	b, err := st.GetScan(ctx, scanB)
	if err != nil {
		return nil, fmt.Errorf("get scan %s: %w", scanB, err)
	}
	if !a.Timestamp.Before(b.Timestamp) {
		return ends, nil
	}
	between, err := st.GetScansByTimeRange(ctx, a.Timestamp, b.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("list scans between %s and %s: %w", scanA, scanB, err)
	}
	var ids []string
	for i := len(between) - 1; i >= 0; i-- {
		if id := between[i].ID; id != scanA && id != scanB {
			ids = append(ids, id)
		}
	}
	if len(ids) > maxDriftScans-2 {
		ids = ids[len(ids)-(maxDriftScans-2):]
	}
	window := make([]report.ScanReport, 0, len(ids)+2)
	window = append(window, ends[0])
	for _, id := range ids {
		r, _, err := loadStoredReport(ctx, st, id)
		if err != nil {
			return nil, err
		}
		window = append(window, report.ScanReport{ID: id, Report: r})
	}
	return append(window, ends[1]), nil
}

// computeWhatChanged returns the structured diff. Findings are matched across
// reports by fingerprint (cluster, scanner, and rule), so a finding whose title
// count changes is neither new nor cleared. The drift ledger is left for the
// caller, which has the store.
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
		if !util.SeverityAtLeast(f.Severity, minSeverity) {
			continue
		}
		out[report.FindingFingerprint(f)] = f
	}
	return out
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

	fmt.Fprintf(w, "Drifted clusters (%d):\n", len(diff.Drift.Clusters))
	if len(diff.Drift.Clusters) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, line := range compare.DriftLines(diff.Drift, maxDriftLines) {
		fmt.Fprintf(w, "  %s\n", line)
	}
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
		fmt.Fprintf(w, "  [%s] %s -- %s\n", strings.ToUpper(f.Severity), f.Cluster, title)
	}
	fmt.Fprintln(w)
}
