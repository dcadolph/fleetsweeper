package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/jsonutil"
	"github.com/dcadolph/fleetsweeper/internal/report"
)

var historyCmd = &cobra.Command{
	Use:   "history",
	Short: "View scan history and trends",
	Long:  "Browse past scans, compare them, and view fleet drift trends.",
}

var historyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List past scans",
	RunE:  runHistoryList,
}

var historyShowCmd = &cobra.Command{
	Use:   "show <scan-id>",
	Short: "Show details of a past scan",
	Args:  cobra.ExactArgs(1),
	RunE:  runHistoryShow,
}

var historyDiffCmd = &cobra.Command{
	Use:   "diff <scan-id-1> <scan-id-2>",
	Short: "Compare two scans",
	Args:  cobra.ExactArgs(2),
	RunE:  runHistoryDiff,
}

var historyTrendCmd = &cobra.Command{
	Use:   "trend",
	Short: "Show fleet drift trends",
	RunE:  runHistoryTrend,
}

func init() {
	historyListCmd.Flags().Int("limit", 20, "Maximum scans to show.")
	historyTrendCmd.Flags().String("cluster", "", "Show trend for a specific cluster.")
	historyTrendCmd.Flags().Int("scans", 10, "Number of historical scans to analyze.")

	historyCmd.AddCommand(historyListCmd)
	historyCmd.AddCommand(historyShowCmd)
	historyCmd.AddCommand(historyDiffCmd)
	historyCmd.AddCommand(historyTrendCmd)
}

// runHistoryList lists past scans from the database.
func runHistoryList(cmd *cobra.Command, _ []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	limit, _ := cmd.Flags().GetInt("limit")
	pretty, _ := cmd.Flags().GetBool("pretty")

	scans, err := s.ListScans(cmd.Context(), limit)
	if err != nil {
		return fmt.Errorf("list scans: %w", err)
	}

	out, err := jsonutil.Marshal(scans, pretty)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(out))
	return nil
}

// runHistoryShow displays a past scan and rebuilds its report.
func runHistoryShow(cmd *cobra.Command, args []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	ctx := cmd.Context()
	pretty, _ := cmd.Flags().GetBool("pretty")

	scan, err := s.GetScan(ctx, args[0])
	if err != nil {
		return fmt.Errorf("get scan: %w", err)
	}

	results, err := s.GetScanResults(ctx, args[0])
	if err != nil {
		return fmt.Errorf("get results: %w", err)
	}

	rpt := report.Build(scan.Clusters, results)
	out, err := jsonutil.Marshal(rpt, pretty)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(out))
	return nil
}

// runHistoryDiff compares two scans and shows what changed.
func runHistoryDiff(cmd *cobra.Command, args []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	ctx := cmd.Context()
	pretty, _ := cmd.Flags().GetBool("pretty")

	scan1, err := s.GetScan(ctx, args[0])
	if err != nil {
		return fmt.Errorf("get scan %s: %w", args[0], err)
	}
	results1, err := s.GetScanResults(ctx, args[0])
	if err != nil {
		return fmt.Errorf("get results %s: %w", args[0], err)
	}

	scan2, err := s.GetScan(ctx, args[1])
	if err != nil {
		return fmt.Errorf("get scan %s: %w", args[1], err)
	}
	results2, err := s.GetScanResults(ctx, args[1])
	if err != nil {
		return fmt.Errorf("get results %s: %w", args[1], err)
	}

	rpt1 := report.Build(scan1.Clusters, results1)
	rpt2 := report.Build(scan2.Clusters, results2)

	diff := buildScanDiff(scan1.ID, scan2.ID, rpt1, rpt2)
	out, err := jsonutil.Marshal(diff, pretty)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(out))
	return nil
}

// scanDiff describes what changed between two scans.
type scanDiff struct {
	// ScanA is the older scan ID.
	ScanA string `json:"scan_a"`
	// ScanB is the newer scan ID.
	ScanB string `json:"scan_b"`
	// ClustersAdded lists clusters present in B but not A.
	ClustersAdded []string `json:"clusters_added,omitempty"`
	// ClustersRemoved lists clusters present in A but not B.
	ClustersRemoved []string `json:"clusters_removed,omitempty"`
	// SummaryDelta shows changes in summary counters.
	SummaryDelta map[string]int `json:"summary_delta"`
	// FindingsAdded lists new findings in B that were not in A.
	FindingsAdded []report.Finding `json:"findings_added,omitempty"`
	// FindingsResolved lists findings in A that are gone in B.
	FindingsResolved []report.Finding `json:"findings_resolved,omitempty"`
}

// buildScanDiff computes the difference between two scan reports.
func buildScanDiff(idA, idB string, a, b *report.Report) *scanDiff {
	d := &scanDiff{
		ScanA:        idA,
		ScanB:        idB,
		SummaryDelta: make(map[string]int),
	}

	aSet := toSet(a.Clusters)
	bSet := toSet(b.Clusters)
	for _, c := range b.Clusters {
		if _, ok := aSet[c]; !ok {
			d.ClustersAdded = append(d.ClustersAdded, c)
		}
	}
	for _, c := range a.Clusters {
		if _, ok := bSet[c]; !ok {
			d.ClustersRemoved = append(d.ClustersRemoved, c)
		}
	}

	d.SummaryDelta["cluster_count"] = b.Summary.ClusterCount - a.Summary.ClusterCount
	d.SummaryDelta["divergent_count"] = b.Summary.DivergentCount - a.Summary.DivergentCount
	d.SummaryDelta["critical_count"] = b.Summary.CriticalCount - a.Summary.CriticalCount
	d.SummaryDelta["warning_count"] = b.Summary.WarningCount - a.Summary.WarningCount
	d.SummaryDelta["total_divergences"] = b.Summary.TotalDivergences - a.Summary.TotalDivergences

	aFindings := findingSet(a.Findings)
	bFindings := findingSet(b.Findings)

	for key, f := range bFindings {
		if _, ok := aFindings[key]; !ok {
			d.FindingsAdded = append(d.FindingsAdded, f)
		}
	}
	for key, f := range aFindings {
		if _, ok := bFindings[key]; !ok {
			d.FindingsResolved = append(d.FindingsResolved, f)
		}
	}

	return d
}

// findingSet creates a map keyed by a finding's identity for diffing.
func findingSet(findings []report.Finding) map[string]report.Finding {
	m := make(map[string]report.Finding, len(findings))
	for _, f := range findings {
		key := f.Severity + "|" + f.Cluster + "|" + f.Scanner + "|" + f.Title
		m[key] = f
	}
	return m
}

// toSet converts a string slice to a set.
func toSet(s []string) map[string]struct{} {
	m := make(map[string]struct{}, len(s))
	for _, v := range s {
		m[v] = struct{}{}
	}
	return m
}

// runHistoryTrend shows fleet drift trends.
func runHistoryTrend(cmd *cobra.Command, _ []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	ctx := cmd.Context()
	pretty, _ := cmd.Flags().GetBool("pretty")
	limit, _ := cmd.Flags().GetInt("scans")
	clusterName, _ := cmd.Flags().GetString("cluster")

	scans, err := s.ListScans(ctx, limit)
	if err != nil {
		return fmt.Errorf("list scans: %w", err)
	}

	if len(scans) < 2 {
		fmt.Fprintln(os.Stderr, "need at least 2 scans for trend analysis")
		return nil
	}

	// Convert store records to report.ScanMeta for the trend functions.
	scanMetas := make([]report.ScanMeta, len(scans))
	for i, s := range scans {
		scanMetas[i] = report.ScanMeta{ID: s.ID, Timestamp: s.Timestamp}
	}

	// Load results for all scans into a flat structure for trend computation.
	resultsByScan := make(map[string]map[string]map[string]any, len(scans))
	for _, scan := range scans {
		raw, err := s.GetScanResults(ctx, scan.ID)
		if err != nil {
			continue
		}
		perCluster := make(map[string]map[string]any)
		for cluster, scanners := range raw {
			for scannerName, result := range scanners {
				if perCluster[cluster] == nil {
					perCluster[cluster] = make(map[string]any)
				}
				// Re-marshal/unmarshal to get flat map[string]any.
				b, _ := json.Marshal(result.Data)
				var m map[string]any
				json.Unmarshal(b, &m)
				perCluster[cluster][scannerName] = m
			}
		}
		resultsByScan[scan.ID] = perCluster
	}

	type trendOutput struct {
		ClusterTrends []report.ClusterTrend `json:"cluster_trends,omitempty"`
		FleetTrends   []report.FleetTrend   `json:"fleet_trends,omitempty"`
		Findings      []report.Finding      `json:"findings,omitempty"`
	}

	var output trendOutput

	if clusterName != "" {
		// Per-cluster data: restructure resultsByScan to be scanID->scanner->fields.
		clusterResults := make(map[string]map[string]map[string]any, len(scans))
		for scanID, perCluster := range resultsByScan {
			if data, ok := perCluster[clusterName]; ok {
				scannerData := make(map[string]map[string]any)
				for scannerName, fields := range data {
					if m, ok := fields.(map[string]any); ok {
						scannerData[scannerName] = m
					}
				}
				clusterResults[scanID] = scannerData
			}
		}
		output.ClusterTrends = report.ComputeClusterTrends(clusterName, scanMetas, clusterResults)
	}

	// Fleet trends: restructure to scanID->clusterName->scannerName->fields.
	fleetResults := make(map[string]map[string]map[string]any, len(scans))
	for scanID, perCluster := range resultsByScan {
		clusterData := make(map[string]map[string]any)
		for cluster, data := range perCluster {
			scannerFields := make(map[string]any)
			for scannerName, fields := range data {
				if m, ok := fields.(map[string]any); ok {
					scannerFields[scannerName] = m
				}
			}
			clusterData[cluster] = scannerFields
		}
		fleetResults[scanID] = clusterData
	}
	output.FleetTrends = report.ComputeFleetTrends(scanMetas, fleetResults)
	output.Findings = report.GenerateTrendFindings(output.ClusterTrends, output.FleetTrends)

	out, err := jsonutil.Marshal(output, pretty)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(out))
	return nil
}
