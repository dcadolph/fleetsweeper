package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/dcadolph/fleetsweeper/internal/fleetdrift"
	"github.com/dcadolph/fleetsweeper/internal/jsonutil"
	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/logutil"
	"github.com/dcadolph/fleetsweeper/internal/policyreport"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/scanner/admission"
	"github.com/dcadolph/fleetsweeper/internal/scanner/certs"
	"github.com/dcadolph/fleetsweeper/internal/scanner/clusterinfo"
	"github.com/dcadolph/fleetsweeper/internal/scanner/crd"
	"github.com/dcadolph/fleetsweeper/internal/scanner/deprecatedapis"
	"github.com/dcadolph/fleetsweeper/internal/scanner/events"
	"github.com/dcadolph/fleetsweeper/internal/scanner/geo"
	"github.com/dcadolph/fleetsweeper/internal/scanner/imageaudit"
	"github.com/dcadolph/fleetsweeper/internal/scanner/ingress"
	"github.com/dcadolph/fleetsweeper/internal/scanner/metrics"
	"github.com/dcadolph/fleetsweeper/internal/scanner/namespace"
	"github.com/dcadolph/fleetsweeper/internal/scanner/networkpolicy"
	"github.com/dcadolph/fleetsweeper/internal/scanner/nodehealth"
	"github.com/dcadolph/fleetsweeper/internal/scanner/policyreportingest"
	"github.com/dcadolph/fleetsweeper/internal/scanner/quota"
	"github.com/dcadolph/fleetsweeper/internal/scanner/rbac"
	"github.com/dcadolph/fleetsweeper/internal/scanner/rbacaudit"
	"github.com/dcadolph/fleetsweeper/internal/scanner/resources"
	"github.com/dcadolph/fleetsweeper/internal/scanner/security"
	"github.com/dcadolph/fleetsweeper/internal/scanner/service"
	"github.com/dcadolph/fleetsweeper/internal/scanner/version"
	"github.com/dcadolph/fleetsweeper/internal/scanner/vulnerabilities"
	"github.com/dcadolph/fleetsweeper/internal/scanner/workloadcoverage"
	"github.com/dcadolph/fleetsweeper/internal/scanner/workloadsec"
	"github.com/dcadolph/fleetsweeper/internal/server"
	"github.com/dcadolph/fleetsweeper/internal/store"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan clusters and compare configurations.",
	Example: "  fleetsweeper scan\n" +
		"  fleetsweeper scan --contexts prod-east,prod-west --db fleet.db -o html --html-file report.html",
	Long: "Connect to every context in the kubeconfig, or the ones --contexts or --group name, and produce " +
		"a comparison report highlighting fleet divergence.",
	RunE: runScan,
}

func init() {
	scanCmd.Flags().StringSlice("contexts", nil, "Kubeconfig context names to scan (default: every context).")
	scanCmd.Flags().Int("workers", 5, "Maximum concurrent operations.")
	scanCmd.Flags().Duration("scanner-timeout", scanner.DefaultScanTimeout, "Maximum time a single scanner may run against one cluster. 0 disables.")
	scanCmd.Flags().StringSlice("scanners", nil, "Scanner names to run (default: all).")
	scanCmd.Flags().StringP("output", "o", "json", "Output format: json or html.")
	scanCmd.Flags().String("html-file", "", "Write HTML report to this file path (implies --output html).")
	scanCmd.Flags().String("group", "", "Scan only clusters in this group (requires --db).")
	scanCmd.Flags().Float64("outlier-threshold", 3.5, "Outlier detection sensitivity (lower=more sensitive).")
	scanCmd.Flags().String("fleetdrift-output", "", "Local directory to write FleetDriftReport YAMLs to (one file per cluster). Empty disables.")
	scanCmd.Flags().String("policy-report-output", "", "Local directory to write wgpolicyk8s.io PolicyReport YAMLs (one file per cluster). Empty disables.")
	scanCmd.Flags().String("policy-report-namespace", "fleetsweeper", "Namespace placed on emitted PolicyReports.")
	scanCmd.Flags().Bool("probe-registries", false, "Resolve image manifests against their registries to report image age. Contacts every registry the fleet pulls from.")
}

// buildRegistry creates the scanner registry with all available scanners.
func buildRegistry() *scanner.Registry {
	r := scanner.NewRegistry()
	r.Register(version.Name, version.NewScanner())
	r.Register(namespace.Name, namespace.NewScanner())
	r.Register(service.Name, service.NewScanner())
	r.Register(ingress.Name, ingress.NewScanner())
	r.Register(rbac.Name, rbac.NewScanner())
	r.Register(networkpolicy.Name, networkpolicy.NewScanner())
	r.Register(security.Name, security.NewScanner())
	r.Register(quota.Name, quota.NewScanner())
	r.Register(crd.Name, crd.NewScanner())
	r.Register(resources.Name, resources.NewScanner())
	r.Register(nodehealth.Name, nodehealth.NewScanner())
	r.Register(metrics.Name, metrics.NewScanner())
	r.Register(events.Name, events.NewScanner())
	r.Register(workloadsec.Name, workloadsec.NewScanner())
	r.Register(rbacaudit.Name, rbacaudit.NewScanner())
	r.Register(imageaudit.Name, imageaudit.NewScanner())
	r.Register(certs.Name, certs.NewScanner())
	r.Register(deprecatedapis.Name, deprecatedapis.NewScanner())
	r.Register(workloadcoverage.Name, workloadcoverage.NewScanner())
	r.Register(clusterinfo.Name, clusterinfo.NewScanner())
	r.Register(admission.Name, admission.NewScanner())
	r.Register(geo.Name, geo.NewScanner())
	r.Register(vulnerabilities.Name, vulnerabilities.NewScanner())
	r.Register(policyreportingest.Name, policyreportingest.NewScanner())
	return r
}

// runScan is the main scan command implementation.
func runScan(cmd *cobra.Command, _ []string) error {
	ctx := cmdContext(cmd)
	log := logutil.UnwrapLogger(ctx)

	stdout, stderr := cmd.OutOrStdout(), cmd.ErrOrStderr()
	kubeconfigPath, _ := cmd.Flags().GetString("kubeconfig")
	pretty, _ := cmd.Flags().GetBool("pretty")
	workers, _ := cmd.Flags().GetInt("workers")
	scannerTimeout, _ := cmd.Flags().GetDuration("scanner-timeout")
	contextNames, _ := cmd.Flags().GetStringSlice("contexts")
	scannerNames, _ := cmd.Flags().GetStringSlice("scanners")
	groupName, _ := cmd.Flags().GetString("group")
	outputFormat, _ := cmd.Flags().GetString("output")
	if err := oneOf("output", outputFormat, "json", "html"); err != nil {
		return err
	}
	probe, _ := cmd.Flags().GetBool("probe-registries")
	imageaudit.SetProbeRegistries(probe)
	registry := buildRegistry()
	selected, err := selectScanners(registry, scannerNames)
	if err != nil {
		return err
	}

	// Resolve contexts from group if specified.
	if groupName != "" {
		s, err := openAnyStore(cmd)
		if err != nil {
			return err
		}
		defer s.Close()
		g, err := s.GetGroup(ctx, groupName)
		if err != nil {
			return fmt.Errorf("get group %q: %w", groupName, err)
		}
		contextNames = g.Clusters
	}

	contexts, err := kube.ResolveContexts(kubeconfigPath, contextNames)
	if err != nil {
		return err
	}

	log.Info("connecting to clusters", zap.Strings("contexts", contexts))
	clients := kube.ConnectAll(ctx, kubeconfigPath, contexts, workers)
	if len(clients) == 0 {
		return ErrNoClients
	}

	log.Info("connected", zap.Int("connected", len(clients)), zap.Int("requested", len(contexts)))

	scannedAt := time.Now().UTC()
	results := server.RunScanners(ctx, clients, selected, workers, scannerTimeout, logutil.UnwrapLogger(ctx))

	clusterNames := make([]string, len(clients))
	for i, c := range clients {
		clusterNames[i] = c.Context
	}

	// Persist results to database when --db is set.
	var st store.Store
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath != "" {
		s, err := openAnyStore(cmd)
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		defer s.Close()
		st = s

		scanID, err := s.SaveScanRecord(ctx, store.ScanRecord{Timestamp: scannedAt, Clusters: clusterNames}, results)
		if err != nil {
			return fmt.Errorf("save scan: %w", err)
		}
		log.Info("scan persisted", zap.String("scan_id", scanID))
		fmt.Fprintf(stderr, "scan %s saved to %s\n", scanID, dbPath)
	}

	outlierThreshold, _ := cmd.Flags().GetFloat64("outlier-threshold")
	rpt, err := buildScanReport(ctx, st, clusterNames, results, report.BuildOptions{
		OutlierThreshold: outlierThreshold,
		Timestamp:        scannedAt,
	})
	if err != nil {
		return err
	}

	// Coverage leads, so a scan that saw little of the fleet never reads as a clean one. This goes
	// to stderr so stdout stays pure report output.
	writeScanSummary(stderr, rpt)

	// Emit FleetDriftReport YAMLs when --fleetdrift-output is set so GitOps
	// pipelines can pick up the drift state. Best-effort: a write failure logs
	// and continues so the operator still gets the JSON/HTML output.
	scanIDForFD := "local-" + time.Now().UTC().Format("20060102T150405Z")
	if dir, _ := cmd.Flags().GetString("fleetdrift-output"); dir != "" {
		reports := fleetdrift.ReportsFor(rpt, scanIDForFD, "")
		if err := fleetdrift.Write(reports, dir); err != nil {
			fmt.Fprintf(stderr, "warning: fleetdrift write failed: %s\n", err)
		} else {
			fmt.Fprintf(stderr, "fleetdrift: wrote %d reports to %s\n", len(reports), dir)
		}
	}
	if dir, _ := cmd.Flags().GetString("policy-report-output"); dir != "" {
		ns, _ := cmd.Flags().GetString("policy-report-namespace")
		reports := policyreport.ReportsFor(rpt, scanIDForFD, ns)
		if err := policyreport.Write(reports, dir); err != nil {
			fmt.Fprintf(stderr, "warning: policyreport write failed: %s\n", err)
		} else {
			fmt.Fprintf(stderr, "policyreport: wrote %d reports to %s\n", len(reports), dir)
		}
	}

	htmlFile, _ := cmd.Flags().GetString("html-file")
	if htmlFile != "" {
		outputFormat = "html"
	}

	switch outputFormat {
	case "html":
		htmlBytes, err := report.RenderHTML(rpt)
		if err != nil {
			return fmt.Errorf("render html: %w", err)
		}
		if htmlFile != "" {
			if err := os.WriteFile(htmlFile, htmlBytes, 0o644); err != nil {
				return fmt.Errorf("write html: %w", err)
			}
			fmt.Fprintf(stderr, "report written to %s\n", htmlFile)
		} else {
			fmt.Fprintln(stdout, string(htmlBytes))
		}
	default:
		out, err := jsonutil.Marshal(rpt, pretty)
		if err != nil {
			return fmt.Errorf("marshal report: %w", err)
		}
		fmt.Fprintln(stdout, string(out))
	}

	return nil
}

// scanSummaryFixes is how many recommendations the terminal summary prints.
const scanSummaryFixes = 3

// writeScanSummary prints the human summary of a scan to w in a fixed order: what the scan
// observed, then the score, then the fixes with the most leverage. Coverage comes first because a
// score is only as good as the runs behind it.
func writeScanSummary(w io.Writer, rpt *report.Report) {
	cov := rpt.FleetScore.Coverage
	clusters := len(rpt.Clusters)
	line := fmt.Sprintf("Coverage: %d of %d scanner runs observed across %d cluster%s.",
		cov.ObservedRuns, cov.ExpectedRuns, clusters, util.Plural(clusters))
	if cov.BlindClusters > 0 {
		line += fmt.Sprintf(" %d cluster%s had no complete run.", cov.BlindClusters, util.Plural(cov.BlindClusters))
	}
	fmt.Fprintln(w, line)
	degraded := rpt.DegradedByCluster()
	for _, c := range slices.Sorted(slices.Values(rpt.Clusters)) {
		if d := degraded[c]; d > 0 {
			fmt.Fprintf(w, "  %s: %d of %d scanners degraded\n", c, d, rpt.Summary.ScannerCount)
		}
	}

	score := fmt.Sprintf("Score: %d (%s).", rpt.FleetScore.Score, rpt.FleetScore.Grade)
	if !rpt.FleetScore.Graded {
		score = "Score: not graded."
	}
	if h := rpt.FleetScore.Headline; h != "" {
		score += " " + h
	}
	fmt.Fprintln(w, score)

	recs := buildRecommendations(rpt.Findings, "")
	for i, r := range recs[:min(len(recs), scanSummaryFixes)] {
		fmt.Fprintf(w, "Fix %d: %s, %s, %d cluster%s (%s).\n", i+1, r.Title, r.Severity, r.Leverage,
			util.Plural(r.Leverage), joinTrim(r.Clusters, 5))
	}

	if len(rpt.Cohorts) > 0 {
		var cohortOutliers int
		for _, c := range rpt.Cohorts {
			cohortOutliers += len(c.Outliers)
		}
		fmt.Fprintf(w, "Cohorts: %d group%s, %d within-cohort outlier%s.\n", len(rpt.Cohorts),
			util.Plural(len(rpt.Cohorts)), cohortOutliers, util.Plural(cohortOutliers))
	}
	if len(rpt.Incidents) > 0 {
		fmt.Fprintf(w, "Incidents: %d fused from correlated findings.\n", len(rpt.Incidents))
	}
}

// selectScanners filters the registry to the requested scanner names. When names is empty all
// scanners are selected. Unknown names return an ErrFlagValue error listing them and the
// registered names.
func selectScanners(registry *scanner.Registry, names []string) (map[string]scanner.Scanner, error) {
	if len(names) == 0 {
		return registry.All(), nil
	}
	selected := make(map[string]scanner.Scanner, len(names))
	var unknown []string
	for _, name := range names {
		s, ok := registry.Get(name)
		if !ok {
			unknown = append(unknown, name)
			continue
		}
		selected[name] = s
	}
	if len(unknown) > 0 {
		return nil, fmt.Errorf("%w: --scanners %s: want any of %s", ErrFlagValue,
			strings.Join(unknown, ", "), strings.Join(registry.Names(), ", "))
	}
	return selected, nil
}

// buildScanReport builds the scan's report. With a store it adds the stored cohort tags and
// groups, so the CLI report partitions cohorts the way the server does for the same scan.
func buildScanReport(ctx context.Context, st store.Store, clusters []string,
	results map[string]map[string]scanner.Result, opts report.BuildOptions) (*report.Report, error) {
	if st != nil {
		stored, err := server.StoreReportOptions(ctx, st)
		if err != nil {
			return nil, fmt.Errorf("load report options: %w", err)
		}
		opts.ClusterTags, opts.Groups = stored.ClusterTags, stored.Groups
	}
	return report.Build(clusters, results, opts), nil
}
