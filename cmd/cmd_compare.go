package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/dcadolph/fleetsweeper/internal/compare"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// compareCmd computes the diff between two stored scans and renders it in
// text (default), JSON, or Markdown.
var compareCmd = &cobra.Command{
	Use:   "compare <scan-a> <scan-b>",
	Short: "Diff two scans: new vs resolved findings, score delta, cluster status changes",
	Long: "Compute a structured diff between two scans and render it. " +
		"Either argument may be a scan ID, 'latest', 'previous', or 'second-latest'. " +
		"Without --format the output is human-readable text; --format markdown is " +
		"suitable for paste into a PR or ticket.",
	Args: cobra.ExactArgs(2),
	RunE: runCompare,
}

func init() {
	compareCmd.Flags().String("format", "text", "Output format: text, markdown, json.")
	compareCmd.Flags().Bool("no-color", false, "Disable ANSI color even on a TTY.")
}

// runCompare is the cobra entrypoint for the compare subcommand.
func runCompare(cmd *cobra.Command, args []string) error {
	ctx := cmdContext(cmd)
	format, _ := cmd.Flags().GetString("format")
	noColor, _ := cmd.Flags().GetBool("no-color")

	s, err := openStore(cmd)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	aID, err := resolveScanID(ctx, s, args[0], 0)
	if err != nil {
		return err
	}
	bID, err := resolveScanID(ctx, s, args[1], 0)
	if err != nil {
		return err
	}

	a, err := loadReport(ctx, s, aID)
	if err != nil {
		return fmt.Errorf("load %q: %w", aID, err)
	}
	b, err := loadReport(ctx, s, bID)
	if err != nil {
		return fmt.Errorf("load %q: %w", bID, err)
	}

	d := compare.Diff(a, b)
	out := cmd.OutOrStdout()
	switch format {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(d)
	case "markdown", "md":
		fmt.Fprint(out, compare.RenderMarkdown(d))
		return nil
	default:
		color := !noColor && term.IsTerminal(int(os.Stdout.Fd()))
		fmt.Fprint(out, compare.RenderText(d, color))
		return nil
	}
}

// resolveScanID maps a friendly alias to an actual scan ID. Recognized
// aliases: 'latest', 'previous' (== second-latest), 'second-latest'.
// Anything else is returned verbatim.
func resolveScanID(ctx context.Context, s *store.SQLite, alias string, _ int) (string, error) {
	switch alias {
	case "latest":
		scans, err := s.ListScans(ctx, 1)
		if err != nil {
			return "", err
		}
		if len(scans) == 0 {
			return "", fmt.Errorf("no scans available")
		}
		return scans[0].ID, nil
	case "previous", "second-latest":
		scans, err := s.ListScans(ctx, 2)
		if err != nil {
			return "", err
		}
		if len(scans) < 2 {
			return "", fmt.Errorf("need at least two scans to use 'previous'")
		}
		return scans[1].ID, nil
	default:
		return alias, nil
	}
}

// loadReport pulls a scan and rebuilds the full Report from its persisted
// raw results.
func loadReport(ctx context.Context, s *store.SQLite, id string) (*report.Report, error) {
	scan, err := s.GetScan(ctx, id)
	if err != nil {
		return nil, err
	}
	results, err := s.GetScanResults(ctx, id)
	if err != nil {
		return nil, err
	}
	return report.Build(scan.Clusters, results), nil
}
