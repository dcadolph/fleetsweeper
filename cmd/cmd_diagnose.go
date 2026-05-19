package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/dcadolph/fleetsweeper/internal/diagnose"
)

// diagnoseCmd runs an end-to-end sanity check across every configured
// integration. Returns a non-zero exit code only when one or more checks
// land in StatusFail; "off" and "warn" are reported but do not fail the
// command so it stays useful in CI pre-flight scripts.
var diagnoseCmd = &cobra.Command{
	Use:   "diagnose",
	Short: "Check that every configured integration is wired up correctly",
	Long: "Run a coloured pass/fail grid of every Fleetsweeper integration. " +
		"By default only local validation runs (URL parsing, file writability). " +
		"Pass --probe to also exercise external systems (Slack webhook, GitHub API).",
	RunE: runDiagnose,
}

func init() {
	diagnoseCmd.Flags().Bool("probe", false, "Actively contact external systems (Slack, GitHub) to validate credentials.")
	diagnoseCmd.Flags().Bool("json", false, "Emit the report as JSON instead of a text table.")
	diagnoseCmd.Flags().String("slack-webhook-url", "", "Slack webhook URL to check (or set $SLACK_WEBHOOK_URL).")
	diagnoseCmd.Flags().String("cost-csv", "", "Path to a cost CSV to parse.")
	diagnoseCmd.Flags().String("policy-report-output", "", "Directory to test-write a PolicyReport into.")
	diagnoseCmd.Flags().String("fleetdrift-output", "", "Directory to test-write a FleetDriftReport into.")
	diagnoseCmd.Flags().String("github-token", "", "GitHub token to validate (or set $GITHUB_TOKEN).")
}

// runDiagnose is the cobra entrypoint for the diagnose subcommand.
func runDiagnose(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()

	probe, _ := cmd.Flags().GetBool("probe")
	jsonOut, _ := cmd.Flags().GetBool("json")

	slack, _ := cmd.Flags().GetString("slack-webhook-url")
	if slack == "" {
		slack = os.Getenv("SLACK_WEBHOOK_URL")
	}
	token, _ := cmd.Flags().GetString("github-token")
	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}
	costCSV, _ := cmd.Flags().GetString("cost-csv")
	prOut, _ := cmd.Flags().GetString("policy-report-output")
	fdOut, _ := cmd.Flags().GetString("fleetdrift-output")
	kubeconfig, _ := cmd.Flags().GetString("kubeconfig")
	db, _ := cmd.Flags().GetString("db")

	report := diagnose.Run(ctx, diagnose.Options{
		KubeconfigPath:        kubeconfig,
		DBPath:                db,
		SlackWebhookURL:       slack,
		CostCSVPath:           costCSV,
		PolicyReportOutputDir: prOut,
		FleetDriftOutputDir:   fdOut,
		GitHubToken:           token,
		Probe:                 probe,
	})

	if jsonOut {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	} else {
		out := cmd.OutOrStdout()
		fd := os.Stdout.Fd()
		fmt.Fprint(out, diagnose.FormatText(report, term.IsTerminal(int(fd))))
	}

	if report.HasFailures() {
		return errors.New("one or more diagnose checks failed")
	}
	return nil
}
