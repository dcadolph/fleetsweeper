package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/remediate"
	"github.com/dcadolph/fleetsweeper/internal/report"
)

// remediateCmd opens a pull request against a GitOps repo for a Fleetsweeper
// finding that ships an inline YAML remediation. Default is dry-run; pass
// --push to actually contact GitHub.
var remediateCmd = &cobra.Command{
	Use:   "remediate",
	Short: "Open a GitOps pull request for a Fleetsweeper finding",
	Long: "Generate (and optionally push) a pull request that adds the inline " +
		"YAML remediation of a Fleetsweeper finding into a GitOps repo. " +
		"Default is dry-run; pass --push and a token to actually open the PR.",
	RunE: runRemediate,
}

func init() {
	remediateCmd.Flags().String("scan-id", "", "Scan ID (required). Use 'latest' for the most recent scan.")
	remediateCmd.Flags().String("cluster", "", "Cluster name (required). The finding is selected from this cluster's findings.")
	remediateCmd.Flags().Int("finding-index", 0, "Zero-based index into the cluster's findings (filtered to those with an inline YAML manifest).")
	remediateCmd.Flags().String("scanner", "", "Optional scanner name filter (e.g. network-policies). Picks the first matching finding with a YAML remediation.")
	remediateCmd.Flags().String("github-repo", "", "GitHub repository as owner/name (required).")
	remediateCmd.Flags().String("github-token", "", "GitHub token. Defaults to $GITHUB_TOKEN when empty.")
	remediateCmd.Flags().String("base-branch", "", "Base branch to target. Empty detects the repo default.")
	remediateCmd.Flags().String("head-branch", "", "Branch name to create. Empty generates one from the finding title.")
	remediateCmd.Flags().String("target-path", "", "In-repo path to write the manifest to. Empty defaults to fleetsweeper/<cluster>/<slug>.yaml.")
	remediateCmd.Flags().Bool("push", false, "Actually create the PR. Without --push the command prints the planned change and exits.")
	remediateCmd.Flags().Bool("plan-json", false, "Emit the plan as JSON to stdout instead of human-readable text.")
	_ = remediateCmd.MarkFlagRequired("scan-id")
	_ = remediateCmd.MarkFlagRequired("cluster")
	_ = remediateCmd.MarkFlagRequired("github-repo")
}

// runRemediate is the cobra entrypoint for the remediate subcommand.
func runRemediate(cmd *cobra.Command, _ []string) error {
	ctx := cmdContext(cmd)

	scanID, _ := cmd.Flags().GetString("scan-id")
	cluster, _ := cmd.Flags().GetString("cluster")
	findingIdx, _ := cmd.Flags().GetInt("finding-index")
	scannerFilter, _ := cmd.Flags().GetString("scanner")
	repoSpec, _ := cmd.Flags().GetString("github-repo")
	token, _ := cmd.Flags().GetString("github-token")
	baseBranch, _ := cmd.Flags().GetString("base-branch")
	headBranch, _ := cmd.Flags().GetString("head-branch")
	targetPath, _ := cmd.Flags().GetString("target-path")
	push, _ := cmd.Flags().GetBool("push")
	planJSON, _ := cmd.Flags().GetBool("plan-json")

	if token == "" {
		token = os.Getenv("GITHUB_TOKEN")
	}

	owner, repoName, err := parseRepoSpec(repoSpec)
	if err != nil {
		return err
	}

	finding, err := pickFinding(ctx, cmd, scanID, cluster, scannerFilter, findingIdx)
	if err != nil {
		return err
	}

	res, err := remediate.Open(ctx, remediate.Options{
		Owner:      owner,
		Repo:       repoName,
		Finding:    finding,
		Cluster:    cluster,
		Token:      token,
		BaseBranch: baseBranch,
		HeadBranch: headBranch,
		TargetPath: targetPath,
		Push:       push,
	})
	if err != nil {
		return fmt.Errorf("remediate: %w", err)
	}

	if planJSON {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}

	printResult(cmd, res)
	return nil
}

// parseRepoSpec splits "owner/repo" into its components.
func parseRepoSpec(s string) (string, string, error) {
	parts := strings.SplitN(s, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("--github-repo must be in the form owner/repo")
	}
	return parts[0], parts[1], nil
}

// pickFinding resolves the requested finding from the store. The "latest"
// scan-id is honored as a convenience so callers do not have to look up a
// scan ID first.
func pickFinding(ctx context.Context, cmd *cobra.Command, scanID, cluster, scannerFilter string, idx int) (report.Finding, error) {
	s, err := openStore(cmd)
	if err != nil {
		return report.Finding{}, fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	if scanID == "latest" {
		scans, err := s.ListScans(ctx, 1)
		if err != nil || len(scans) == 0 {
			return report.Finding{}, fmt.Errorf("no scans available")
		}
		scanID = scans[0].ID
	}

	scan, err := s.GetScan(ctx, scanID)
	if err != nil {
		return report.Finding{}, fmt.Errorf("get scan %q: %w", scanID, err)
	}
	results, err := s.GetScanResults(ctx, scan.ID)
	if err != nil {
		return report.Finding{}, fmt.Errorf("get scan results: %w", err)
	}
	rpt := report.Build(scan.Clusters, results)

	candidates := filterRemediable(rpt.Findings, cluster, scannerFilter)
	if len(candidates) == 0 {
		return report.Finding{}, fmt.Errorf("no remediable findings (with inline YAML) for cluster %q matched", cluster)
	}
	if idx < 0 || idx >= len(candidates) {
		return report.Finding{}, fmt.Errorf("--finding-index %d out of range; %d remediable finding(s) available", idx, len(candidates))
	}
	return candidates[idx], nil
}

// filterRemediable returns only findings that target the cluster (or are
// fleet-scoped) AND ship an inline YAML manifest the remediator can apply.
func filterRemediable(findings []report.Finding, cluster, scannerFilter string) []report.Finding {
	out := make([]report.Finding, 0, len(findings))
	for _, f := range findings {
		if f.Cluster != cluster && f.Cluster != "fleet" && f.Cluster != "" {
			continue
		}
		if scannerFilter != "" && f.Scanner != scannerFilter {
			continue
		}
		if f.Remediation == nil || strings.TrimSpace(f.Remediation.YAML) == "" {
			continue
		}
		out = append(out, f)
	}
	return out
}

// printResult renders the result in a compact human-readable form.
func printResult(cmd *cobra.Command, res remediate.Result) {
	out := cmd.OutOrStdout()
	if res.DryRun {
		fmt.Fprintln(out, "dry run: nothing was pushed")
	} else {
		fmt.Fprintf(out, "PR opened: %s (#%d)\n", res.PRURL, res.PRNumber)
	}
	fmt.Fprintf(out, "  head: %s\n  base: %s\n  path: %s\n  title: %s\n",
		res.HeadBranch, res.BaseBranch, res.TargetPath, res.PRTitle)
	if res.DryRun {
		fmt.Fprintln(out, "\nplanned YAML:")
		fmt.Fprintln(out, res.PlannedYAML)
	}
}
