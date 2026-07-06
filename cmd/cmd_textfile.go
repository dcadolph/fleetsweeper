package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// textfileCmd writes Prometheus textfile-collector-compatible .prom
// files so node_exporter (or any textfile collector) picks up
// Fleetsweeper metrics without running the HTTP server.
var textfileCmd = &cobra.Command{
	Use:   "export-metrics <output-dir>",
	Short: "Write Prometheus textfile-collector .prom files",
	Long: "Reads the latest scan from the configured store and writes a\n" +
		"fleetsweeper.prom file (atomically, via a .tmp rename) into\n" +
		"<output-dir>. The directory is the path node_exporter watches\n" +
		"via --collector.textfile.directory. Run on a cron or systemd timer.",
	Args: cobra.ExactArgs(1),
	RunE: runExportMetrics,
}

func init() {
	textfileCmd.Flags().String("filename", "fleetsweeper.prom", "Filename for the metrics file. Useful when colocating multiple exporters.")
}

// runExportMetrics implements the export-metrics subcommand.
func runExportMetrics(cmd *cobra.Command, args []string) error {
	outDir := args[0]
	filename, _ := cmd.Flags().GetString("filename")

	st, err := openAnyStore(cmd)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := cmd.Context()
	rpt, scanID, err := latestReport(ctx, st)
	if err != nil {
		return err
	}
	if rpt == nil {
		return fmt.Errorf("no scans found in store")
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %q: %w", outDir, err)
	}
	final := filepath.Join(outDir, filename)
	tmp := final + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open %q: %w", tmp, err)
	}
	if err := writeProm(f, rpt, scanID, time.Now().UTC()); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close %q: %w", tmp, err)
	}
	if err := os.Rename(tmp, final); err != nil {
		return fmt.Errorf("rename %q -> %q: %w", tmp, final, err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", final)
	return nil
}

// latestReport pulls the most recent scan and rebuilds the Report.
// Returns (nil, "", nil) when the store has no scans yet.
func latestReport(ctx context.Context, st store.Store) (*report.Report, string, error) {
	scans, err := st.ListScans(ctx, 1)
	if err != nil {
		return nil, "", fmt.Errorf("list scans: %w", err)
	}
	if len(scans) == 0 {
		return nil, "", nil
	}
	results, err := st.GetScanResults(ctx, scans[0].ID)
	if err != nil {
		return nil, "", fmt.Errorf("get scan results: %w", err)
	}
	rpt := report.Build(scans[0].Clusters, results)
	return rpt, scans[0].ID, nil
}

// writeProm renders the report as Prometheus textfile-collector lines.
// Metric names follow the fleetsweeper_<noun>_<unit> convention so they
// blend with the rest of the metrics surface exposed at /metrics.
func writeProm(w io.Writer, rpt *report.Report, scanID string, now time.Time) error {
	fmt.Fprintln(w, "# HELP fleetsweeper_fleet_score Overall fleet health score in [0, 100].")
	fmt.Fprintln(w, "# TYPE fleetsweeper_fleet_score gauge")
	fmt.Fprintf(w, "fleetsweeper_fleet_score{scan_id=%q} %d\n", scanID, rpt.FleetScore.Score)

	fmt.Fprintln(w, "# HELP fleetsweeper_fleet_score_timestamp_seconds When the scan was emitted.")
	fmt.Fprintln(w, "# TYPE fleetsweeper_fleet_score_timestamp_seconds gauge")
	fmt.Fprintf(w, "fleetsweeper_fleet_score_timestamp_seconds %d\n", now.Unix())

	fmt.Fprintln(w, "# HELP fleetsweeper_findings_total Findings emitted by the most recent scan, by severity.")
	fmt.Fprintln(w, "# TYPE fleetsweeper_findings_total gauge")
	fmt.Fprintf(w, "fleetsweeper_findings_total{severity=\"critical\"} %d\n", rpt.Summary.CriticalCount)
	fmt.Fprintf(w, "fleetsweeper_findings_total{severity=\"warning\"} %d\n", rpt.Summary.WarningCount)

	fmt.Fprintln(w, "# HELP fleetsweeper_clusters_total Clusters analyzed in the most recent scan.")
	fmt.Fprintln(w, "# TYPE fleetsweeper_clusters_total gauge")
	fmt.Fprintf(w, "fleetsweeper_clusters_total %d\n", rpt.Summary.ClusterCount)

	fmt.Fprintln(w, "# HELP fleetsweeper_cluster_score Per-cluster health score in [0, 100].")
	fmt.Fprintln(w, "# TYPE fleetsweeper_cluster_score gauge")
	scores := report.ComputeClusterScores(rpt)
	sort.Slice(scores, func(i, j int) bool { return scores[i].Cluster < scores[j].Cluster })
	for _, s := range scores {
		fmt.Fprintf(w, "fleetsweeper_cluster_score{cluster=%q,grade=%q} %d\n",
			escapeLabel(s.Cluster), s.Grade, s.Score)
	}

	if len(rpt.Outliers) > 0 {
		fmt.Fprintln(w, "# HELP fleetsweeper_cluster_outlier Whether the cluster is currently flagged as a fleet outlier.")
		fmt.Fprintln(w, "# TYPE fleetsweeper_cluster_outlier gauge")
		seen := map[string]bool{}
		for _, o := range rpt.Outliers {
			if seen[o.Cluster] {
				continue
			}
			seen[o.Cluster] = true
			fmt.Fprintf(w, "fleetsweeper_cluster_outlier{cluster=%q} 1\n", escapeLabel(o.Cluster))
		}
	}

	return nil
}

// escapeLabel applies the Prometheus label-value escaping rules: backslash,
// double-quote, and newline are escaped. The exposition format is otherwise
// flexible enough to carry kubeconfig context names as-is.
func escapeLabel(v string) string {
	if !strings.ContainsAny(v, `\"`+"\n") {
		return v
	}
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)
	return r.Replace(v)
}
