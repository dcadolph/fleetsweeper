package cmd

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"

	"github.com/dcadolph/fleetsweeper/internal/cost"
	"github.com/dcadolph/fleetsweeper/internal/fleetdrift"
	"github.com/dcadolph/fleetsweeper/internal/policyreport"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/seal"
)

// exportCmd writes a single tar.gz bundle containing the JSON report, HTML
// report, PolicyReport YAMLs, FleetDriftReport YAMLs, and (optionally) the
// cost analysis. Designed for security and compliance handoffs that want
// one file rather than a directory of separate artifacts.
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Bundle a scan as a tar.gz of report + PolicyReports + FleetDrift + cost",
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
	exportCmd.Flags().String("seal-key", "", "HMAC-SHA256 secret for sealing report.json. Empty skips sealing.")
}

// runExport is the cobra entrypoint for the export subcommand.
func runExport(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	scanID, _ := cmd.Flags().GetString("scan-id")
	output, _ := cmd.Flags().GetString("output")
	costCSV, _ := cmd.Flags().GetString("cost-csv")
	prNS, _ := cmd.Flags().GetString("policy-report-namespace")
	sealKey, _ := cmd.Flags().GetString("seal-key")
	if sealKey == "" {
		sealKey = os.Getenv("FLEETSWEEPER_SEAL_KEY")
	}

	s, err := openStore(cmd)
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
	rpt := report.Build(scan.Clusters, results)

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

	if err := writeBundle(sink, ctx, rpt, scan.ID, costCSV, prNS, sealKey); err != nil {
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

// writeBundle streams a gzipped tar containing every artifact derived from
// the report into sink. Each file lives under a single top-level directory
// named for the scan so tar extraction does not splatter into the cwd.
// When sealKey is non-empty, the bundle includes a report.sig file with
// the HMAC-SHA256 signature of report.json, suitable for "fleetsweeper
// verify" tamper detection.
func writeBundle(sink io.Writer, ctx context.Context, rpt *report.Report, scanID, costCSVPath, prNS, sealKey string) error {
	gz := gzip.NewWriter(sink)
	defer gz.Close()
	tw := tar.NewWriter(gz)
	defer tw.Close()

	root := "fleetsweeper-export-" + sanitize(scanID)
	now := time.Now().UTC()

	if err := writeMetadata(tw, root, rpt, scanID, now, sealKey != ""); err != nil {
		return err
	}

	reportBytes, err := json.Marshal(rpt)
	if err != nil {
		return err
	}
	if err := writeTarFile(tw, path.Join(root, seal.SourceFile), reportBytes); err != nil {
		return err
	}
	if err := writeJSONFile(tw, path.Join(root, "report.pretty.json"), rpt, true); err != nil {
		return err
	}
	if sealKey != "" {
		sig, err := seal.Sign(reportBytes, sealKey)
		if err != nil {
			return fmt.Errorf("seal report: %w", err)
		}
		if err := writeTarFile(tw, path.Join(root, seal.FileName), []byte(sig+"\n")); err != nil {
			return err
		}
	}

	htmlBytes, err := report.RenderHTML(rpt)
	if err == nil {
		if err := writeTarFile(tw, path.Join(root, "report.html"), htmlBytes); err != nil {
			return err
		}
	}

	prReports := policyreport.ReportsFor(rpt, scanID, prNS)
	for _, pr := range prReports {
		data, err := yaml.Marshal(pr)
		if err != nil {
			return err
		}
		if err := writeTarFile(tw,
			path.Join(root, "policyreports", pr.Metadata.Name+".yaml"), data); err != nil {
			return err
		}
	}

	fdReports := fleetdrift.ReportsFor(rpt, scanID, "")
	for _, fd := range fdReports {
		data, err := yaml.Marshal(fd)
		if err != nil {
			return err
		}
		if err := writeTarFile(tw,
			path.Join(root, "fleetdrift", fd.Metadata.Name+".yaml"), data); err != nil {
			return err
		}
	}

	if costCSVPath != "" {
		costs, err := cost.LoadCSV(costCSVPath)
		if err == nil {
			analysis := cost.Correlate(rpt, costs)
			if err := writeJSONFile(tw, path.Join(root, "cost.json"), analysis, true); err != nil {
				return err
			}
		}
	}

	_ = ctx
	return nil
}

// writeMetadata creates a human-readable METADATA.txt at the bundle root so
// auditors who open the tarball see what they're looking at without parsing
// JSON. When sealed is true the manifest documents the report.sig entry so
// auditors know the bundle is verifiable with "fleetsweeper verify".
func writeMetadata(tw *tar.Writer, root string, rpt *report.Report, scanID string, now time.Time, sealed bool) error {
	var b strings.Builder
	fmt.Fprintf(&b, "Fleetsweeper export bundle\n")
	fmt.Fprintf(&b, "==========================\n\n")
	fmt.Fprintf(&b, "Scan ID:       %s\n", scanID)
	fmt.Fprintf(&b, "Scan time:     %s\n", rpt.Timestamp)
	fmt.Fprintf(&b, "Exported at:   %s\n", now.Format(time.RFC3339))
	fmt.Fprintf(&b, "Cluster count: %d\n", len(rpt.Clusters))
	fmt.Fprintf(&b, "Fleet score:   %d (%s)\n", rpt.FleetScore.Score, rpt.FleetScore.Grade)
	fmt.Fprintf(&b, "Findings:      %d total (%d critical, %d warning)\n",
		len(rpt.Findings), rpt.Summary.CriticalCount, rpt.Summary.WarningCount)
	fmt.Fprintf(&b, "Sealed:        %t\n", sealed)
	fmt.Fprintf(&b, "\nContents:\n")
	fmt.Fprintf(&b, "  report.json           Full JSON report (compact)\n")
	fmt.Fprintf(&b, "  report.pretty.json    Same content, indented for human reading\n")
	fmt.Fprintf(&b, "  report.html           Self-contained HTML dashboard\n")
	fmt.Fprintf(&b, "  policyreports/        wgpolicyk8s.io PolicyReport YAML per cluster\n")
	fmt.Fprintf(&b, "  fleetdrift/           FleetDriftReport YAML per cluster\n")
	fmt.Fprintf(&b, "  cost.json             Cost correlation (when --cost-csv was provided)\n")
	if sealed {
		fmt.Fprintf(&b, "  report.sig            HMAC-SHA256 of report.json (run 'fleetsweeper verify')\n")
	}
	return writeTarFile(tw, path.Join(root, "METADATA.txt"), []byte(b.String()))
}

// writeJSONFile marshals v and writes it as a tar entry. When pretty is true
// the output is indented with two spaces.
func writeJSONFile(tw *tar.Writer, name string, v any, pretty bool) error {
	var data []byte
	var err error
	if pretty {
		data, err = json.MarshalIndent(v, "", "  ")
	} else {
		data, err = json.Marshal(v)
	}
	if err != nil {
		return err
	}
	return writeTarFile(tw, name, data)
}

// writeTarFile writes a single regular file into the tar archive.
func writeTarFile(tw *tar.Writer, name string, data []byte) error {
	hdr := &tar.Header{
		Name:    filepath.ToSlash(name),
		Mode:    0o644,
		Size:    int64(len(data)),
		ModTime: time.Now().UTC(),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	_, err := tw.Write(data)
	return err
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
