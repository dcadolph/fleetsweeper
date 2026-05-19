package cmd

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"

	"github.com/dcadolph/fleetsweeper/internal/admission"
)

// baselineCmd is the parent command for fleet-baseline operations.
var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Inspect, export, and diff the fleet admission baseline",
	Long: "The admission baseline is the set of fleet-wide fractions the\n" +
		"admission webhook compares incoming pods against. This subcommand\n" +
		"prints, exports, and diffs that baseline so operators can pin and\n" +
		"audit their fleet norm.",
}

// baselineShowCmd prints the current baseline as YAML.
var baselineShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print the current admission baseline as YAML",
	RunE:  runBaselineShow,
}

// baselineExportCmd writes the current baseline to a file.
var baselineExportCmd = &cobra.Command{
	Use:   "export <path>",
	Short: "Write the current admission baseline to a YAML file",
	Args:  cobra.ExactArgs(1),
	RunE:  runBaselineExport,
}

// baselineDiffCmd compares a saved baseline against the current one.
var baselineDiffCmd = &cobra.Command{
	Use:   "diff <path>",
	Short: "Compare a saved baseline against the current one",
	Args:  cobra.ExactArgs(1),
	RunE:  runBaselineDiff,
}

func init() {
	baselineDiffCmd.Flags().Float64("epsilon", 0.05, "Maximum allowed drift per fraction before the diff is flagged as a regression. Default 0.05 (5pp).")
	baselineCmd.AddCommand(baselineShowCmd)
	baselineCmd.AddCommand(baselineExportCmd)
	baselineCmd.AddCommand(baselineDiffCmd)
}

// loadBaseline opens the configured store and returns the current baseline.
func loadBaseline(cmd *cobra.Command) (admission.Baseline, error) {
	st, err := openAnyStore(cmd)
	if err != nil {
		return admission.Baseline{}, err
	}
	defer st.Close()
	provider := admission.NewStoreBaselineProvider(st, 0)
	return provider.Current(context.Background()), nil
}

// runBaselineShow prints the current baseline as YAML.
func runBaselineShow(cmd *cobra.Command, _ []string) error {
	b, err := loadBaseline(cmd)
	if err != nil {
		return err
	}
	return yamlEncode(cmd.OutOrStdout(), b)
}

// runBaselineExport writes the current baseline to the given path.
func runBaselineExport(cmd *cobra.Command, args []string) error {
	b, err := loadBaseline(cmd)
	if err != nil {
		return err
	}
	body, err := yaml.Marshal(b)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.WriteFile(args[0], body, 0o644); err != nil {
		return fmt.Errorf("write %q: %w", args[0], err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "wrote %s\n", args[0])
	return nil
}

// runBaselineDiff compares a saved baseline against the current one.
// Non-zero exit when any fraction drift exceeds --epsilon.
func runBaselineDiff(cmd *cobra.Command, args []string) error {
	cur, err := loadBaseline(cmd)
	if err != nil {
		return err
	}
	body, err := os.ReadFile(args[0])
	if err != nil {
		return fmt.Errorf("read %q: %w", args[0], err)
	}
	var saved admission.Baseline
	if err := yaml.Unmarshal(body, &saved); err != nil {
		return fmt.Errorf("parse %q: %w", args[0], err)
	}
	epsilon, _ := cmd.Flags().GetFloat64("epsilon")

	type drift struct {
		Field   string
		Saved   float64
		Current float64
		Delta   float64
	}
	drifts := []drift{
		{"digest_pin_fraction", saved.DigestPinFraction, cur.DigestPinFraction, cur.DigestPinFraction - saved.DigestPinFraction},
		{"non_root_fraction", saved.NonRootFraction, cur.NonRootFraction, cur.NonRootFraction - saved.NonRootFraction},
		{"no_privilege_escalation_fraction", saved.NoPrivilegeEscalationFraction, cur.NoPrivilegeEscalationFraction, cur.NoPrivilegeEscalationFraction - saved.NoPrivilegeEscalationFraction},
		{"named_service_account_fraction", saved.NamedServiceAccountFraction, cur.NamedServiceAccountFraction, cur.NamedServiceAccountFraction - saved.NamedServiceAccountFraction},
		{"read_only_root_fs_fraction", saved.ReadOnlyRootFSFraction, cur.ReadOnlyRootFSFraction, cur.ReadOnlyRootFSFraction - saved.ReadOnlyRootFSFraction},
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%-35s  %8s  %8s  %8s\n", "field", "saved", "current", "delta")
	fmt.Fprintf(cmd.OutOrStdout(), "%-35s  %8s  %8s  %8s\n", "-----", "-----", "-------", "-----")
	regressed := false
	for _, d := range drifts {
		fmt.Fprintf(cmd.OutOrStdout(), "%-35s  %8.3f  %8.3f  %+8.3f\n",
			d.Field, d.Saved, d.Current, d.Delta)
		if math.Abs(d.Delta) > epsilon {
			regressed = true
		}
	}
	if regressed {
		return errors.New("baseline drift exceeds epsilon")
	}
	return nil
}

// yamlEncode writes a YAML representation of v to w.
func yamlEncode(w yamlWriter, v any) error {
	body, err := yaml.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

// yamlWriter is the io.Writer shape yamlEncode needs.
type yamlWriter interface {
	Write(p []byte) (int, error)
}
