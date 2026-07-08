package cmd

import (
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
)

// watchCmd reruns a scan on an interval and prints a diff between
// consecutive runs. Useful during incidents and rollouts when you want to
// see the fleet move in real time without staring at a dashboard.
var watchCmd = &cobra.Command{
	Use:   "watch",
	Short: "Repeatedly scan and print a diff between consecutive runs",
	Long: "Run a scan on the given interval and print the diff to the " +
		"previous run. By default no results are persisted; pass --db to " +
		"also save each scan into the SQLite store.",
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
	interval, _ := cmd.Flags().GetDuration("interval")
	maxRuns, _ := cmd.Flags().GetInt("max-runs")
	onChangeOnly, _ := cmd.Flags().GetBool("on-change-only")
	noColor, _ := cmd.Flags().GetBool("no-color")
	color := !noColor && term.IsTerminal(int(os.Stdout.Fd()))

	contexts, err := resolveContexts(kubeconfigPath, contextNames, allContexts)
	if err != nil {
		return err
	}

	registry := buildRegistry()
	selected := selectScanners(registry, scannerNames)

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
			results := runScanners(ctx, clients, selected, workers, scanner.DefaultScanTimeout)
			clusterNames := make([]string, len(clients))
			for i, c := range clients {
				clusterNames[i] = c.Context
			}
			cur := report.Build(clusterNames, results)
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

// diffHasChanges reports whether the diff carries any meaningful change.
// Used by --on-change-only to suppress empty repeats.
func diffHasChanges(d compare.ScanDiff) bool {
	return len(d.New) > 0 || len(d.Resolved) > 0 ||
		len(d.ClusterStatusChanges) > 0 ||
		len(d.AddedClusters) > 0 || len(d.RemovedClusters) > 0 ||
		d.ScoreAfter != d.ScoreBefore
}
