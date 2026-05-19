package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/dcadolph/fleetsweeper/internal/explain"
)

// whyCmd prints an operator-facing explainer for a Fleetsweeper topic.
// Usage:
//
//	fleetsweeper why fleet-score
//	fleetsweeper why memory-pressure
//	fleetsweeper why "policy stand"
//	fleetsweeper why list
var whyCmd = &cobra.Command{
	Use:   "why <topic>",
	Short: "Explain what a Fleetsweeper finding or scanner means",
	Long: "Print a rich explanation of a Fleetsweeper concept: what it means, " +
		"how the severity is computed, suggested remediation, and related " +
		"topics. Pass 'list' to see all available topics.",
	Args: cobra.MinimumNArgs(1),
	RunE: runWhy,
}

func init() {
	whyCmd.Flags().Bool("no-color", false, "Disable ANSI colour even on a TTY.")
}

// runWhy is the cobra entrypoint for the why subcommand.
func runWhy(cmd *cobra.Command, args []string) error {
	key := strings.Join(args, " ")
	noColor, _ := cmd.Flags().GetBool("no-color")
	color := !noColor && term.IsTerminal(int(os.Stdout.Fd()))

	out := cmd.OutOrStdout()

	if strings.EqualFold(key, "list") {
		fmt.Fprintln(out, "Available topics:")
		for _, k := range explain.Keys() {
			fmt.Fprintf(out, "  %s\n", k)
		}
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Aliases and substring matches are accepted.")
		return nil
	}

	topic := explain.Lookup(key)
	if topic == nil {
		fmt.Fprintf(out, "No topic matched %q. Run `fleetsweeper why list` to see options.\n", key)
		return fmt.Errorf("topic not found: %s", key)
	}
	fmt.Fprint(out, explain.Render(*topic, color))
	return nil
}
