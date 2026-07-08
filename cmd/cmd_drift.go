package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/dcadolph/fleetsweeper/internal/admission"
	"github.com/dcadolph/fleetsweeper/internal/kube"
)

// driftCmd inspects every pod in a kubeconfig context and reports which
// ones deviate from the admission baseline. Same checks as the
// validating admission webhook, but applied as a one-shot audit so
// teams can gate CI without installing the webhook in-cluster.
var driftCmd = &cobra.Command{
	Use:   "drift",
	Short: "Check every pod in a context against the admission baseline",
	Long: "Lists pods across the chosen context (defaults to current-context)\n" +
		"and applies the admission baseline checks locally. Useful as a\n" +
		"pre-flight CI gate: scan a staging cluster, fail the build when any\n" +
		"workload drifts away from the fleet norm.",
	RunE: runDrift,
}

func init() {
	driftCmd.Flags().String("context", "", "Kubeconfig context to inspect. Defaults to the current-context.")
	driftCmd.Flags().String("namespace", "", "Restrict the scan to a single namespace. Empty scans all namespaces.")
	driftCmd.Flags().String("baseline", "", "Path to a baseline YAML produced by `fleetsweeper baseline export`. Empty derives the baseline from --db.")
	driftCmd.Flags().Bool("json", false, "Emit JSON instead of the human-readable table.")
	driftCmd.Flags().Bool("fail-on-drift", false, "Exit non-zero when any pod drifts. Default just prints the report.")
}

// driftFinding is one pod's per-check outcome.
type driftFinding struct {
	// Namespace is the pod's namespace.
	Namespace string `json:"namespace"`
	// Pod is the pod name.
	Pod string `json:"pod"`
	// Warnings are the per-check messages aggregated across checks.
	Warnings []string `json:"warnings,omitempty"`
	// DenyReasons are the per-check deny strings (enforce mode would 403).
	DenyReasons []string `json:"deny_reasons,omitempty"`
}

// driftReport is the full drift output.
type driftReport struct {
	// Context is the kubeconfig context inspected.
	Context string `json:"context"`
	// Baseline summarizes the fleet norm used.
	Baseline admission.Baseline `json:"baseline"`
	// TotalPods is the number of pods inspected.
	TotalPods int `json:"total_pods"`
	// DriftedPods is the number of pods with at least one warning.
	DriftedPods int `json:"drifted_pods"`
	// Findings is the per-pod detail, only including pods with warnings.
	Findings []driftFinding `json:"findings"`
}

// runDrift implements the drift subcommand.
func runDrift(cmd *cobra.Command, _ []string) error {
	contextName, _ := cmd.Flags().GetString("context")
	namespace, _ := cmd.Flags().GetString("namespace")
	baselinePath, _ := cmd.Flags().GetString("baseline")
	jsonOut, _ := cmd.Flags().GetBool("json")
	failOnDrift, _ := cmd.Flags().GetBool("fail-on-drift")
	kubeconfigPath, _ := cmd.Flags().GetString("kubeconfig")

	ctx := cmdContext(cmd)

	baseline, err := resolveDriftBaseline(cmd, baselinePath)
	if err != nil {
		return err
	}

	client, err := kube.NewClient(ctx, kubeconfigPath, contextName)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}
	resolvedContext := client.Context
	if resolvedContext == "" {
		resolvedContext = contextName
	}

	pods, err := listPods(ctx, client, namespace)
	if err != nil {
		return fmt.Errorf("list pods: %w", err)
	}

	checks := admission.DefaultChecks()
	report := driftReport{
		Context:   resolvedContext,
		Baseline:  baseline,
		TotalPods: len(pods),
	}
	for i := range pods {
		f := evaluatePod(&pods[i], checks, baseline)
		if len(f.Warnings) == 0 && len(f.DenyReasons) == 0 {
			continue
		}
		report.DriftedPods++
		report.Findings = append(report.Findings, f)
	}

	sort.Slice(report.Findings, func(i, j int) bool {
		a, b := report.Findings[i], report.Findings[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Pod < b.Pod
	})

	if err := writeDriftReport(cmd.OutOrStdout(), report, jsonOut); err != nil {
		return err
	}
	if failOnDrift && report.DriftedPods > 0 {
		return fmt.Errorf("drift detected: %d/%d pods", report.DriftedPods, report.TotalPods)
	}
	return nil
}

// resolveDriftBaseline returns the baseline to compare against. When
// --baseline points at a YAML file the contents are parsed; otherwise
// the store is opened and the latest baseline is recomputed.
func resolveDriftBaseline(cmd *cobra.Command, baselinePath string) (admission.Baseline, error) {
	if baselinePath != "" {
		body, err := os.ReadFile(baselinePath)
		if err != nil {
			return admission.Baseline{}, fmt.Errorf("read baseline: %w", err)
		}
		var b admission.Baseline
		if err := yaml.Unmarshal(body, &b); err != nil {
			return admission.Baseline{}, fmt.Errorf("parse baseline: %w", err)
		}
		return b, nil
	}
	return loadBaseline(cmd)
}

// listPods returns every pod in the requested scope. Empty namespace
// lists across all namespaces.
func listPods(ctx context.Context, c *kube.Client, namespace string) ([]corev1.Pod, error) {
	list, err := c.Clientset().CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

// evaluatePod applies every Check to a pod and folds the warnings.
func evaluatePod(pod *corev1.Pod, checks []admission.Check, baseline admission.Baseline) driftFinding {
	f := driftFinding{Namespace: pod.Namespace, Pod: pod.Name}
	for _, c := range checks {
		warns, deny := c.Evaluate(pod, baseline)
		f.Warnings = append(f.Warnings, warns...)
		if deny != "" {
			f.DenyReasons = append(f.DenyReasons, deny)
		}
	}
	return f
}

// writeDriftReport renders report to w in the chosen format.
func writeDriftReport(w io.Writer, report driftReport, jsonOut bool) error {
	if jsonOut {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
	fmt.Fprintf(w, "Context:        %s\n", report.Context)
	fmt.Fprintf(w, "Pods inspected: %d\n", report.TotalPods)
	fmt.Fprintf(w, "Pods drifted:   %d\n", report.DriftedPods)
	fmt.Fprintf(w, "Source scan:    %s\n", report.Baseline.SourceScanID)
	fmt.Fprintln(w, "")
	if len(report.Findings) == 0 {
		fmt.Fprintln(w, "No drift detected. Pods are consistent with the fleet norm.")
		return nil
	}
	for _, f := range report.Findings {
		fmt.Fprintf(w, "[%s/%s]\n", f.Namespace, f.Pod)
		for _, warn := range f.Warnings {
			fmt.Fprintf(w, "  warn: %s\n", warn)
		}
		for _, deny := range f.DenyReasons {
			fmt.Fprintf(w, "  deny: %s\n", deny)
		}
	}
	return nil
}
