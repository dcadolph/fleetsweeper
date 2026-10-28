package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/dcadolph/fleetsweeper/internal/compare"
)

// compareCmd computes the diff between two stored scans and renders it in
// text (default), JSON, or Markdown.
var compareCmd = &cobra.Command{
	Use:   "compare <scan-a> <scan-b>",
	Short: "Diff two scans: new vs resolved findings, score delta, cluster status changes.",
	Example: "  fleetsweeper compare 41 42 --db fleet.db\n" +
		"  fleetsweeper compare 41 42 --db fleet.db --format markdown",
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
	if err := oneOf("format", format, "text", "markdown", "md", "json"); err != nil {
		return err
	}
	noColor, _ := cmd.Flags().GetBool("no-color")

	s, err := openAnyStore(cmd)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	aID, err := resolveScanRef(ctx, s, args[0])
	if err != nil {
		return err
	}
	bID, err := resolveScanRef(ctx, s, args[1])
	if err != nil {
		return err
	}

	a, _, err := loadStoredReport(ctx, s, aID)
	if err != nil {
		return fmt.Errorf("load %q: %w", aID, err)
	}
	b, _, err := loadStoredReport(ctx, s, bID)
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
