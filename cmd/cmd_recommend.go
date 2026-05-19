package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/report"
)

// recommendCmd synthesises an ordered "do this next" list from the
// remediations attached to the most recent scan. The ordering favours
// remediations that would fix the same problem on many clusters at
// once — that's where the operator's effort goes furthest.
var recommendCmd = &cobra.Command{
	Use:   "recommend",
	Short: "Prioritised action items derived from the latest scan",
	Long: "Walks the latest scan's findings, collapses identical\n" +
		"remediations across clusters, and prints a ranked list. The\n" +
		"hero metric is leverage: a remediation that fixes ten clusters\n" +
		"is worth ten times the same remediation on one cluster.",
	RunE: runRecommend,
}

func init() {
	recommendCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable text.")
	recommendCmd.Flags().Int("limit", 25, "Maximum number of recommendations to print.")
	recommendCmd.Flags().String("severity", "", "Only consider findings at or above this severity (critical, warning, info).")
}

// Recommendation is one collapsed remediation across clusters.
type recommendation struct {
	// Title is the human-readable label of the finding.
	Title string `json:"title"`
	// Scanner is the producing scanner name.
	Scanner string `json:"scanner"`
	// Severity is the highest severity seen across the contributing rows.
	Severity string `json:"severity"`
	// Clusters lists every cluster the remediation would apply to.
	Clusters []string `json:"clusters"`
	// Command is the suggested kubectl/CLI invocation.
	Command string `json:"command,omitempty"`
	// YAML is a manifest snippet the operator can apply directly.
	YAML string `json:"yaml,omitempty"`
	// RunbookURL is the optional runbook link.
	RunbookURL string `json:"runbook_url,omitempty"`
	// Leverage is the count of clusters this recommendation would fix.
	Leverage int `json:"leverage"`
}

// runRecommend implements the recommend subcommand.
func runRecommend(cmd *cobra.Command, _ []string) error {
	st, err := openAnyStore(cmd)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := cmd.Context()
	rpt, _, err := latestReport(ctx, st)
	if err != nil {
		return err
	}
	if rpt == nil {
		return fmt.Errorf("no scans found in store")
	}

	severity, _ := cmd.Flags().GetString("severity")
	limit, _ := cmd.Flags().GetInt("limit")
	recs := buildRecommendations(rpt.Findings, severity)
	if limit > 0 && len(recs) > limit {
		recs = recs[:limit]
	}

	jsonOut, _ := cmd.Flags().GetBool("json")
	return writeRecommendations(cmd.OutOrStdout(), recs, jsonOut)
}

// buildRecommendations groups findings by (scanner, title) when both
// have a non-empty Remediation, ranks the groups by leverage * severity,
// and returns one Recommendation per group.
func buildRecommendations(findings []report.Finding, minSeverity string) []recommendation {
	type key struct {
		Scanner, Title string
	}
	groups := map[key]*recommendation{}
	for _, f := range findings {
		if f.Remediation == nil {
			continue
		}
		if !severityAtLeast(f.Severity, minSeverity) {
			continue
		}
		k := key{Scanner: f.Scanner, Title: f.Title}
		entry := groups[k]
		if entry == nil {
			entry = &recommendation{
				Title:      f.Title,
				Scanner:    f.Scanner,
				Severity:   f.Severity,
				Command:    f.Remediation.Command,
				YAML:       f.Remediation.YAML,
				RunbookURL: f.Remediation.RunbookURL,
			}
			groups[k] = entry
		}
		if !containsCluster(entry.Clusters, f.Cluster) {
			entry.Clusters = append(entry.Clusters, f.Cluster)
			entry.Leverage++
		}
		// Promote severity to the highest seen across contributing rows.
		if recommendSeverityRank(f.Severity) > recommendSeverityRank(entry.Severity) {
			entry.Severity = f.Severity
		}
	}

	out := make([]recommendation, 0, len(groups))
	for _, g := range groups {
		sort.Strings(g.Clusters)
		out = append(out, *g)
	}
	sort.SliceStable(out, func(i, j int) bool {
		scoreI := out[i].Leverage * (recommendSeverityRank(out[i].Severity) + 1)
		scoreJ := out[j].Leverage * (recommendSeverityRank(out[j].Severity) + 1)
		if scoreI != scoreJ {
			return scoreI > scoreJ
		}
		if out[i].Leverage != out[j].Leverage {
			return out[i].Leverage > out[j].Leverage
		}
		return out[i].Title < out[j].Title
	})
	return out
}

// recommendSeverityRank orders the report severities the same way
// severityAtLeast in whatchanged does. Local copy avoids a cross-file
// alias.
func recommendSeverityRank(s string) int {
	switch s {
	case "critical":
		return 3
	case "warning":
		return 2
	case "info":
		return 1
	}
	return 0
}

// containsCluster reports whether the slice already includes c.
func containsCluster(in []string, c string) bool {
	for _, v := range in {
		if v == c {
			return true
		}
	}
	return false
}

// writeRecommendations renders the list to w in the chosen format.
func writeRecommendations(w io.Writer, recs []recommendation, jsonOut bool) error {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(recs)
	}
	if len(recs) == 0 {
		fmt.Fprintln(w, "No actionable remediations found in the latest scan.")
		return nil
	}
	for i, r := range recs {
		fmt.Fprintf(w, "%d. [%s] %s\n", i+1, strings.ToUpper(r.Severity), r.Title)
		fmt.Fprintf(w, "   Scanner:  %s\n", r.Scanner)
		fmt.Fprintf(w, "   Leverage: %d cluster(s) — %s\n", r.Leverage, joinTrim(r.Clusters, 5))
		if r.Command != "" {
			fmt.Fprintf(w, "   Run:      %s\n", r.Command)
		}
		if r.YAML != "" {
			fmt.Fprintln(w, "   Apply:")
			for _, line := range strings.Split(strings.TrimRight(r.YAML, "\n"), "\n") {
				fmt.Fprintf(w, "     %s\n", line)
			}
		}
		if r.RunbookURL != "" {
			fmt.Fprintf(w, "   Runbook:  %s\n", r.RunbookURL)
		}
		fmt.Fprintln(w)
	}
	return nil
}

// joinTrim joins up to max names with ", " and appends an
// "(+N more)" suffix when the list is clipped.
func joinTrim(in []string, max int) string {
	if len(in) <= max {
		return strings.Join(in, ", ")
	}
	return strings.Join(in[:max], ", ") + fmt.Sprintf(" (+%d more)", len(in)-max)
}
