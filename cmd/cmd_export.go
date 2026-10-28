package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/cost"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/seal"
)

// exportCmd writes a single tar.gz bundle containing the JSON report, HTML
// report, raw scan results, PolicyReport YAMLs, FleetDriftReport YAMLs, and
// (optionally) the cost analysis. The same scan always exports to the same
// bytes, and a sealed bundle carries a signed MANIFEST of every file. Designed for security and compliance handoffs that want
// one file rather than a directory of separate artifacts.
var exportCmd = &cobra.Command{
	Use:     "export",
	Short:   "Bundle a scan as a tar.gz of report + PolicyReports + FleetDrift + cost.",
	Example: "  fleetsweeper export --db fleet.db --output scan.tar.gz --seal-key \"$SEAL_KEY\"",
	Long: "Read a scan from the database and produce a single tar.gz containing " +
		"the JSON report, HTML report, per-cluster PolicyReport CRs, per-cluster " +
		"FleetDriftReport CRs, and (when --cost-csv is provided) a cost analysis. " +
		"Useful for security audits, compliance handoffs, and scan archival.",
	RunE: runExport,
}

func init() {
	exportCmd.Flags().String("scan-id", "latest", "Scan ID to export (or 'latest' for the most recent).")
	exportCmd.Flags().String("output", "", "Output tar.gz path. Empty writes to stdout.")
	exportCmd.Flags().String("cost-csv", "", "Optional cost CSV to include as cost.json in the bundle.")
	exportCmd.Flags().String("policy-report-namespace", "fleetsweeper", "Namespace placed on emitted PolicyReports.")
	exportCmd.Flags().String("seal-key", "", "HMAC-SHA256 secret that signs the bundle's MANIFEST of every file. Empty skips sealing.")
}

// runExport is the cobra entrypoint for the export subcommand.
func runExport(cmd *cobra.Command, _ []string) error {
	ctx := cmdContext(cmd)
	scanID, _ := cmd.Flags().GetString("scan-id")
	output, _ := cmd.Flags().GetString("output")
	costCSV, _ := cmd.Flags().GetString("cost-csv")
	prNS, _ := cmd.Flags().GetString("policy-report-namespace")
	sealKey, _ := cmd.Flags().GetString("seal-key")
	if sealKey == "" {
		sealKey = os.Getenv("FLEETSWEEPER_SEAL_KEY")
	}

	s, err := openAnyStore(cmd)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	if scanID == "latest" {
		scans, err := s.ListScans(ctx, 1)
		if err != nil || len(scans) == 0 {
			return fmt.Errorf("no scans available")
		}
		scanID = scans[0].ID
	}

	scan, err := s.GetScan(ctx, scanID)
	if err != nil {
		return fmt.Errorf("get scan %q: %w", scanID, err)
	}
	results, err := s.GetScanResults(ctx, scan.ID)
	if err != nil {
		return fmt.Errorf("get scan results: %w", err)
	}
	rpt := report.Build(scan.Clusters, results, report.BuildOptions{Timestamp: scan.Timestamp})

	opts := seal.BundleOptions{PolicyReportNamespace: prNS, Sealed: sealKey != ""}
	if costCSV != "" {
		costs, err := cost.LoadCSV(costCSV)
		if err != nil {
			return fmt.Errorf("load cost csv: %w", err)
		}
		analysis := cost.Correlate(rpt, costs)
		opts.Cost = &analysis
	}
	files, err := seal.BundleFiles(rpt, results, scan.ID, opts)
	if err != nil {
		return fmt.Errorf("build bundle: %w", err)
	}
	if sealKey != "" {
		if _, err := seal.Bundle(files, sealKey); err != nil {
			return fmt.Errorf("seal bundle: %w", err)
		}
	}

	var sink io.Writer
	var closeSink func() error = func() error { return nil }
	if output == "" {
		sink = cmd.OutOrStdout()
	} else {
		f, err := os.Create(output)
		if err != nil {
			return fmt.Errorf("create output: %w", err)
		}
		sink = f
		closeSink = f.Close
	}

	root := "fleetsweeper-export-" + sanitize(scan.ID)
	if err := seal.WriteBundle(sink, root, files, scan.Timestamp); err != nil {
		_ = closeSink()
		return fmt.Errorf("write bundle: %w", err)
	}
	if err := closeSink(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}

	if output != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "wrote bundle: %s\n", output)
	}
	return nil
}

// sanitize keeps the scan-id safe for use in a tar entry path.
func sanitize(s string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9', r == '-', r == '_':
			return r
		default:
			return '-'
		}
	}, s)
	if out == "" {
		return "scan"
	}
	return out
}
