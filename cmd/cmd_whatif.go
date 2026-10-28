package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// whatifCmd projects how the fleet norm and score move if one cluster's field
// were fixed. It rebuilds a stored scan with the fix applied and writes
// nothing.
var whatifCmd = &cobra.Command{
	Use:     "whatif",
	Short:   "Project the score and fleet norm if one cluster's field were fixed.",
	Example: "  fleetsweeper whatif --db fleet.db --cluster c04 --field security/enforced_count",
	Long: "Rebuilds a stored scan with one cluster's field set to the norm and\n" +
		"reports the fleet score before and after, how the field's median and\n" +
		"MAD move, and which other clusters become or stop being outliers once\n" +
		"the norm shifts. Fix kinds: median (numeric fields), mode (string\n" +
		"fields), consensus (adds the set members the cluster lacks), and\n" +
		"remove (takes the cluster out of the population). Nothing is written.",
	Args: cobra.NoArgs,
	RunE: runWhatif,
}

func init() {
	whatifCmd.Flags().String("cluster", "", "Cluster to fix. Required.")
	whatifCmd.Flags().String("field", "", "Field to fix as scanner/field, e.g. security/enforced_count. Required.")
	whatifCmd.Flags().String("fix", "", "Fix kind: median, mode, consensus, or remove. Empty picks the one that fits the field.")
	whatifCmd.Flags().String("norm", report.NormScopeFleet, "Norm to fix toward: fleet or a cohort name.")
	whatifCmd.Flags().String("scan-id", "latest", "Scan to project from, or 'latest'.")
	whatifCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable text.")
}

// runWhatif is the cobra entrypoint for the whatif subcommand.
func runWhatif(cmd *cobra.Command, _ []string) error {
	cluster, _ := cmd.Flags().GetString("cluster")
	field, _ := cmd.Flags().GetString("field")
	scannerName, fieldName, ok := strings.Cut(field, "/")
	if cluster == "" || !ok || scannerName == "" || fieldName == "" {
		return fmt.Errorf("--cluster and --field scanner/field are required")
	}
	kind, _ := cmd.Flags().GetString("fix")
	norm, _ := cmd.Flags().GetString("norm")
	scanID, _ := cmd.Flags().GetString("scan-id")
	jsonOut, _ := cmd.Flags().GetBool("json")

	st, err := openAnyStore(cmd)
	if err != nil {
		return err
	}
	defer st.Close()
	ctx := cmdContext(cmd)

	if scanID, err = resolveScanRef(ctx, st, scanID); err != nil {
		return err
	}
	sc, err := loadStoredScan(ctx, st, scanID)
	if err != nil {
		return err
	}

	fix := report.Fix{Cluster: cluster, Scanner: scannerName, Field: fieldName, Kind: kind, Scope: norm}
	out, err := report.WhatIf(sc.Record.Clusters, sc.Results, sc.Opts, fix)
	if err != nil {
		return err
	}
	return writeWhatif(cmd.OutOrStdout(), out, jsonOut)
}

// writeWhatif renders a what-if outcome to w as JSON or text.
func writeWhatif(w io.Writer, out report.Outcome, jsonOut bool) error {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	}
	f := out.Fix
	fmt.Fprintf(w, "What if %s %s/%s were fixed (%s, %s norm)?\n", f.Cluster, f.Scanner, f.Field, f.Kind, f.Scope)
	fmt.Fprintf(w, "Fleet score: %d -> %d (%+d)\n", out.ScoreBefore, out.ScoreAfter, out.ScoreAfter-out.ScoreBefore)
	switch {
	case out.After == nil:
		fmt.Fprintln(w, "Norm: every cluster agrees on the field after the fix.")
	case out.Before.Kind == report.NormKindNumeric:
		fmt.Fprintf(w, "Norm: median %s -> %s, MAD %s -> %s\n",
			num(out.Before.Median), num(out.After.Median), num(out.Before.MAD), num(out.After.MAD))
	case out.Before.Kind == report.NormKindString:
		fmt.Fprintf(w, "Norm: mode %q at %.0f%% -> %q at %.0f%%\n",
			out.Before.Mode, out.Before.ModeShare*100, out.After.Mode, out.After.ModeShare*100)
	default:
		fmt.Fprintf(w, "Norm: %d consensus members -> %d\n", len(out.Before.Consensus), len(out.After.Consensus))
	}
	fmt.Fprintf(w, "Newly flagged: %s\n", listOrNone(out.NewOutliers))
	fmt.Fprintf(w, "No longer flagged: %s\n", listOrNone(out.ClearedOutliers))
	fmt.Fprintln(w, "Nothing was changed. This is a projection from the stored scan.")
	return nil
}

// num formats a float without trailing zeros.
func num(v float64) string {
	return fmt.Sprintf("%g", v)
}

// listOrNone joins names with ", ", or returns "none".
func listOrNone(names []string) string {
	if len(names) == 0 {
		return "none"
	}
	return strings.Join(names, ", ")
}
