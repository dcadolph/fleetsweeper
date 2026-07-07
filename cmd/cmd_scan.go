package cmd

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

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
	"github.com/dcadolph/fleetsweeper/internal/tracing"
)

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan clusters and compare configurations",
	Long:  "Connect to multiple Kubernetes clusters and produce a comparison report highlighting fleet divergence.",
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().StringSlice("contexts", nil, "Kubeconfig context names to scan.")
	scanCmd.Flags().Bool("all-contexts", false, "Scan all contexts in the kubeconfig.")
	scanCmd.Flags().Int("workers", 5, "Maximum concurrent operations.")
	scanCmd.Flags().StringSlice("scanners", nil, "Scanner names to run (default: all).")
	scanCmd.Flags().StringP("output", "o", "json", "Output format: json or html.")
	scanCmd.Flags().String("html-file", "", "Write HTML report to this file path (implies --output html).")
	scanCmd.Flags().String("group", "", "Scan only clusters in this group (requires --db).")
	scanCmd.Flags().Float64("outlier-threshold", 3.5, "Outlier detection sensitivity (lower=more sensitive).")
	scanCmd.Flags().String("fleetdrift-output", "", "Local directory to write FleetDriftReport YAMLs to (one file per cluster). Empty disables.")
	scanCmd.Flags().String("policy-report-output", "", "Local directory to write wgpolicyk8s.io PolicyReport YAMLs (one file per cluster). Empty disables.")
	scanCmd.Flags().String("policy-report-namespace", "fleetsweeper", "Namespace placed on emitted PolicyReports.")
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
	ctx := cmd.Context()
	log := logutil.UnwrapLogger(ctx)

	kubeconfigPath, _ := cmd.Flags().GetString("kubeconfig")
	pretty, _ := cmd.Flags().GetBool("pretty")
	workers, _ := cmd.Flags().GetInt("workers")
	allContexts, _ := cmd.Flags().GetBool("all-contexts")
	contextNames, _ := cmd.Flags().GetStringSlice("contexts")
	scannerNames, _ := cmd.Flags().GetStringSlice("scanners")
	groupName, _ := cmd.Flags().GetString("group")
	if probe, _ := cmd.Flags().GetBool("probe-registries"); probe {
		imageaudit.SetProbeRegistries(true)
	}

	// Resolve contexts from group if specified.
	if groupName != "" {
		s, err := openStore(cmd)
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

	contexts, err := resolveContexts(kubeconfigPath, contextNames, allContexts)
	if err != nil {
		return err
	}

	log.Info("connecting to clusters", logutil.ContextField(fmt.Sprintf("%v", contexts)))
	clients := kube.ConnectAll(ctx, kubeconfigPath, contexts, workers)
	if len(clients) == 0 {
		return ErrNoClients
	}

	log.Info("connected", logutil.ContextField(fmt.Sprintf("%d/%d clusters", len(clients), len(contexts))))

	registry := buildRegistry()
	selected := selectScanners(registry, scannerNames)

	results := runScanners(ctx, clients, selected, workers)

	clusterNames := make([]string, len(clients))
	for i, c := range clients {
		clusterNames[i] = c.Context
	}

	// Persist results to database when --db is set.
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath != "" {
		s, err := openStore(cmd)
		if err != nil {
			return fmt.Errorf("open store: %w", err)
		}
		defer s.Close()

		scanID, err := s.SaveScan(ctx, clusterNames, results)
		if err != nil {
			return fmt.Errorf("save scan: %w", err)
		}
		log.Info("scan persisted", logutil.ContextField(scanID))
		fmt.Fprintf(os.Stderr, "scan %s saved to %s\n", scanID, dbPath)
	}

	outlierThreshold, _ := cmd.Flags().GetFloat64("outlier-threshold")
	rpt := report.Build(clusterNames, results, report.BuildOptions{
		OutlierThreshold: outlierThreshold,
	})

	// Surface degraded coverage so a forbidden or unreachable API never reads
	// as a clean, zero-resource cluster. This goes to stderr so stdout stays
	// pure report output.
	if degraded := rpt.DegradedByCluster(); len(degraded) > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d scanner run(s) did not return trustworthy data across %d cluster(s); coverage is partial\n",
			len(rpt.Degraded), len(degraded))
		for _, c := range clusterNames {
			if d := degraded[c]; d > 0 {
				fmt.Fprintf(os.Stderr, "  %s: %d of %d scanners degraded\n", c, d, len(selected))
			}
		}
	}

	// Surface cohort partitioning and the within-cohort outliers, which catch
	// drift the fleet-wide view drowns out.
	if len(rpt.Cohorts) > 0 {
		var cohortOutliers int
		for _, c := range rpt.Cohorts {
			cohortOutliers += len(c.Outliers)
		}
		fmt.Fprintf(os.Stderr, "cohorts: %d group(s), %d within-cohort outlier(s)\n",
			len(rpt.Cohorts), cohortOutliers)
	}
	if len(rpt.Incidents) > 0 {
		fmt.Fprintf(os.Stderr, "incidents: %d fused from correlated findings\n", len(rpt.Incidents))
	}

	// Emit FleetDriftReport YAMLs when --fleetdrift-output is set so GitOps
	// pipelines can pick up the drift state. Best-effort: a write failure logs
	// and continues so the operator still gets the JSON/HTML output.
	scanIDForFD := "local-" + time.Now().UTC().Format("20060102T150405Z")
	if dir, _ := cmd.Flags().GetString("fleetdrift-output"); dir != "" {
		reports := fleetdrift.ReportsFor(rpt, scanIDForFD, "")
		if err := fleetdrift.Write(reports, dir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: fleetdrift write failed: %s\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "fleetdrift: wrote %d reports to %s\n", len(reports), dir)
		}
	}
	if dir, _ := cmd.Flags().GetString("policy-report-output"); dir != "" {
		ns, _ := cmd.Flags().GetString("policy-report-namespace")
		reports := policyreport.ReportsFor(rpt, scanIDForFD, ns)
		if err := policyreport.Write(reports, dir); err != nil {
			fmt.Fprintf(os.Stderr, "warning: policyreport write failed: %s\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "policyreport: wrote %d reports to %s\n", len(reports), dir)
		}
	}

	outputFormat, _ := cmd.Flags().GetString("output")
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
			fmt.Fprintf(os.Stderr, "report written to %s\n", htmlFile)
		} else {
			fmt.Fprintln(os.Stdout, string(htmlBytes))
		}
	default:
		out, err := jsonutil.Marshal(rpt, pretty)
		if err != nil {
			return fmt.Errorf("marshal report: %w", err)
		}
		fmt.Fprintln(os.Stdout, string(out))
	}

	return nil
}

// resolveContexts determines which kubeconfig contexts to scan.
func resolveContexts(kubeconfigPath string, explicit []string, all bool) ([]string, error) {
	if all {
		return kube.AvailableContexts(kubeconfigPath)
	}
	if len(explicit) > 0 {
		return explicit, nil
	}
	return nil, ErrNoContexts
}

// selectScanners filters the registry to the requested scanner names. When
// names is empty all scanners are selected.
func selectScanners(registry *scanner.Registry, names []string) map[string]scanner.Scanner {
	if len(names) == 0 {
		return registry.All()
	}
	selected := make(map[string]scanner.Scanner, len(names))
	for _, name := range names {
		if s, ok := registry.Get(name); ok {
			selected[name] = s
		}
	}
	return selected
}

// runScanners executes all selected scanners against all clients concurrently.
// A root "fleetsweeper.scan" span wraps the fan-out and one child span per
// scanner-cluster pair records timing and success. When no OTel exporter is
// configured the spans drop silently.
func runScanners(ctx context.Context, clients []*kube.Client, scanners map[string]scanner.Scanner, workers int) map[string]map[string]scanner.Result {
	log := logutil.UnwrapLogger(ctx)

	ctx, rootSpan := tracing.Tracer().Start(ctx, "fleetsweeper.scan",
		trace.WithAttributes(
			attribute.Int("fleetsweeper.cluster_count", len(clients)),
			attribute.Int("fleetsweeper.scanner_count", len(scanners)),
		),
	)
	defer rootSpan.End()

	var mu sync.Mutex
	results := make(map[string]map[string]scanner.Result)
	for _, c := range clients {
		results[c.Context] = make(map[string]scanner.Result)
	}

	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, client := range clients {
		for name, s := range scanners {
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				continue
			}
			wg.Add(1)
			go func(c *kube.Client, scanName string, sc scanner.Scanner) {
				defer wg.Done()
				defer func() { <-sem }()

				spanCtx, span := tracing.Tracer().Start(ctx, "fleetsweeper.scanner."+scanName,
					trace.WithAttributes(
						attribute.String("fleetsweeper.cluster", c.Context),
						attribute.String("fleetsweeper.scanner", scanName),
					),
				)
				defer span.End()

				res, err := sc.Scan(spanCtx, c)
				if err != nil {
					span.RecordError(err)
					span.SetStatus(codes.Error, "scanner failed")
					log.Warn("scanner failed",
						logutil.ContextField(c.Context),
						logutil.ErrorField(err),
					)
					res = scanner.ErroredResult(scanName, err)
				} else {
					span.SetStatus(codes.Ok, "")
				}

				mu.Lock()
				results[c.Context][scanName] = res
				mu.Unlock()
			}(client, name, s)
		}
	}

	wg.Wait()
	return results
}
