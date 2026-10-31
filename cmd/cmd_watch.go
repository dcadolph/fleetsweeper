package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/dcadolph/fleetsweeper/internal/compare"
	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/logutil"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/scanner/imageaudit"
	"github.com/dcadolph/fleetsweeper/internal/server"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// watchCmd reruns a scan on an interval and prints a diff between
// consecutive runs. Useful during incidents and rollouts when you want to
// see the fleet move in real time without staring at a dashboard.
var watchCmd = &cobra.Command{
	Use:     "watch",
	Short:   "Repeatedly scan and print a diff between consecutive runs.",
	Example: "  fleetsweeper watch --all-contexts --interval 10m --on-change-only",
	Long: "Run a scan on the given interval and print the diff to the " +
		"previous run. By default no results are persisted; pass --db to " +
		"also save each scan into the store.",
	RunE: runWatch,
}

func init() {
	watchCmd.Flags().StringSlice("contexts", nil, "Kubeconfig context names to scan.")
	watchCmd.Flags().Bool("all-contexts", false, "Scan all contexts in the kubeconfig.")
	watchCmd.Flags().Int("workers", 5, "Maximum concurrent operations.")
	watchCmd.Flags().StringSlice("scanners", nil, "Scanner names to run (default: all).")
	watchCmd.Flags().Duration("interval", 5*time.Minute, "Pause between scans.")
	watchCmd.Flags().Int("max-runs", 0, "Stop after N scans (0 = infinite).")
	watchCmd.Flags().Bool("on-change-only", false, "Only print when the diff is non-empty.")
	watchCmd.Flags().Bool("no-color", false, "Disable ANSI color even on a TTY.")
	watchCmd.Flags().Duration("scanner-timeout", scanner.DefaultScanTimeout, "Maximum time a single scanner may run against one cluster. 0 disables.")
	watchCmd.Flags().Bool("probe-registries", false, "Resolve image manifests against their registries to report image age. Contacts every registry the fleet pulls from.")
}

// runWatch is the cobra entrypoint for the watch subcommand.
func runWatch(cmd *cobra.Command, _ []string) error {
	ctx := cmdContext(cmd)
	log := logutil.UnwrapLogger(ctx)

	kubeconfigPath, _ := cmd.Flags().GetString("kubeconfig")
	allContexts, _ := cmd.Flags().GetBool("all-contexts")
	contextNames, _ := cmd.Flags().GetStringSlice("contexts")
	scannerNames, _ := cmd.Flags().GetStringSlice("scanners")
	workers, _ := cmd.Flags().GetInt("workers")
	scannerTimeout, _ := cmd.Flags().GetDuration("scanner-timeout")
	interval, _ := cmd.Flags().GetDuration("interval")
	maxRuns, _ := cmd.Flags().GetInt("max-runs")
	onChangeOnly, _ := cmd.Flags().GetBool("on-change-only")
	noColor, _ := cmd.Flags().GetBool("no-color")
	color := !noColor && term.IsTerminal(int(os.Stdout.Fd()))

	contexts, err := resolveContexts(kubeconfigPath, contextNames, allContexts)
	if err != nil {
		return err
	}

	probe, _ := cmd.Flags().GetBool("probe-registries")
	imageaudit.SetProbeRegistries(probe)
	registry := buildRegistry()
	selected, err := selectScanners(registry, scannerNames)
	if err != nil {
		return err
	}

	var st store.Store
	if dbPath, _ := cmd.Flags().GetString("db"); dbPath != "" {
		st, err = openAnyStore(cmd)
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		defer st.Close()
	}

	out := cmd.OutOrStdout()
	var prev *report.Report
	runs := 0

	fmt.Fprintf(out, "fleetsweeper watch: scanning %d cluster(s), interval %s\n",
		len(contexts), interval)

	for {
		runs++
		fmt.Fprintf(out, "\n----- run %d at %s -----\n", runs, time.Now().Format(time.RFC3339))

		clients := kube.ConnectAll(ctx, kubeconfigPath, contexts, workers)
		if len(clients) == 0 {
			log.Warn("watch: no clients reached")
		} else {
			cur, err := watchOnce(ctx, clients, selected, workers, scannerTimeout, st)
			if err != nil {
				return err
			}
			d := compare.Diff(prev, cur)
			if !onChangeOnly || diffHasChanges(d) {
				fmt.Fprint(out, compare.RenderText(d, color))
			} else {
				fmt.Fprintln(out, "(no changes since previous run)")
			}
			prev = cur
		}

		if maxRuns > 0 && runs >= maxRuns {
			return nil
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(interval):
		}
	}
}

// watchOnce scans the clients and returns the report built from the results. When st is
// non-nil it saves the scan and builds the report with the store's cohort tags and groups.
func watchOnce(ctx context.Context, clients []*kube.Client, selected map[string]scanner.Scanner,
	workers int, timeout time.Duration, st store.Store) (*report.Report, error) {
	scannedAt := time.Now().UTC()
	results := server.RunScanners(ctx, clients, selected, workers, timeout, logutil.UnwrapLogger(ctx))
	names := make([]string, len(clients))
	for i, c := range clients {
		names[i] = c.Context
	}
	if st != nil {
		id, err := st.SaveScanRecord(ctx, store.ScanRecord{Timestamp: scannedAt, Clusters: names}, results)
		if err != nil {
			return nil, fmt.Errorf("save scan: %w", err)
		}
		fmt.Fprintf(os.Stderr, "scan %s saved\n", id)
	}
	return buildScanReport(ctx, st, names, results, report.BuildOptions{Timestamp: scannedAt})
}

// diffHasChanges reports whether the diff carries any meaningful change.
// Used by --on-change-only to suppress empty repeats.
func diffHasChanges(d compare.ScanDiff) bool {
	return len(d.New) > 0 || len(d.Resolved) > 0 ||
		len(d.ClusterStatusChanges) > 0 ||
		len(d.AddedClusters) > 0 || len(d.RemovedClusters) > 0 ||
		d.GradedBefore != d.GradedAfter || (d.ScoreComparable() && d.ScoreAfter != d.ScoreBefore)
}
