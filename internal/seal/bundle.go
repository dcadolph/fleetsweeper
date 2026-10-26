package seal

import (
	"archive/tar"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"slices"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/dcadolph/fleetsweeper/internal/cost"
	"github.com/dcadolph/fleetsweeper/internal/fleetdrift"
	"github.com/dcadolph/fleetsweeper/internal/policyreport"
	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// DefaultPolicyReportNamespace is the namespace placed on bundled PolicyReports when
// BundleOptions leaves it empty. The server's seal endpoint always uses it, so an export made
// with the default seals to the same signature as the endpoint.
const DefaultPolicyReportNamespace = "fleetsweeper"

// maxBundleBytes caps how much ReadBundle decompresses, so a hostile archive cannot exhaust
// memory.
const maxBundleBytes = 1 << 30

// ErrUnsealed is returned when verifying a bundle that has no MANIFEST or no signature.
var ErrUnsealed = errors.New("seal: bundle is not sealed")

// ErrBundle is returned when a bundle archive is not in the layout WriteBundle produces.
var ErrBundle = errors.New("seal: bundle is malformed")

// BundleOptions selects the optional contents of an export bundle.
type BundleOptions struct {
	// PolicyReportNamespace is the namespace on bundled PolicyReports. Empty means
	// DefaultPolicyReportNamespace.
	PolicyReportNamespace string
	// Cost is the cost correlation to include as cost.json. Nil leaves it out.
	Cost *cost.Analysis
	// Sealed records in METADATA.txt that the bundle carries a MANIFEST and signature.
	Sealed bool
}

// BundleFiles returns every file of the export bundle for one stored scan, keyed by path
// relative to the bundle root. Every file derives from rpt, results, scanID, and opts alone, so
// the same scan yields the same bytes on every call. rpt must be built with the scan's own
// timestamp for that to hold.
func BundleFiles(rpt *report.Report, results map[string]map[string]scanner.Result, scanID string,
	opts BundleOptions) (map[string][]byte, error) {
	ns := opts.PolicyReportNamespace
	if ns == "" {
		ns = DefaultPolicyReportNamespace
	}
	files := make(map[string][]byte)
	add := func(name string, v any, pretty bool) error {
		var data []byte
		var err error
		if pretty {
			data, err = json.MarshalIndent(v, "", "  ")
		} else {
			data, err = json.Marshal(v)
		}
		if err != nil {
			return fmt.Errorf("marshal %s: %w", name, err)
		}
		files[name] = data
		return nil
	}

	files["METADATA.txt"] = metadata(rpt, scanID, opts)
	if err := add("report.json", rpt, false); err != nil {
		return nil, err
	}
	if err := add("report.pretty.json", rpt, true); err != nil {
		return nil, err
	}
	if err := add("scan_results.json", results, false); err != nil {
		return nil, err
	}
	html, err := report.RenderHTML(rpt)
	if err != nil {
		return nil, fmt.Errorf("render report.html: %w", err)
	}
	files["report.html"] = html

	for _, pr := range policyreport.ReportsFor(rpt, scanID, ns) {
		data, err := yaml.Marshal(pr)
		if err != nil {
			return nil, fmt.Errorf("marshal policy report %s: %w", pr.Metadata.Name, err)
		}
		files[path.Join("policyreports", pr.Metadata.Name+".yaml")] = data
	}
	for _, fd := range fleetdrift.ReportsFor(rpt, scanID, "") {
		data, err := yaml.Marshal(fd)
		if err != nil {
			return nil, fmt.Errorf("marshal fleet drift report %s: %w", fd.Metadata.Name, err)
		}
		files[path.Join("fleetdrift", fd.Metadata.Name+".yaml")] = data
	}
	if opts.Cost != nil {
		if err := add("cost.json", opts.Cost, true); err != nil {
			return nil, err
		}
	}
	return files, nil
}

// metadata renders METADATA.txt, the human-readable summary at the bundle root. It carries no
// export time, so exporting the same scan twice yields the same file.
func metadata(rpt *report.Report, scanID string, opts BundleOptions) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "Fleetsweeper export bundle\n")
	fmt.Fprintf(&b, "==========================\n\n")
	fmt.Fprintf(&b, "Scan ID:       %s\n", scanID)
	fmt.Fprintf(&b, "Scan time:     %s\n", rpt.Timestamp)
	fmt.Fprintf(&b, "Cluster count: %d\n", len(rpt.Clusters))
	fmt.Fprintf(&b, "Fleet score:   %d (%s)\n", rpt.FleetScore.Score, rpt.FleetScore.Grade)
	fmt.Fprintf(&b, "Scored from:   %d cluster(s) across %d dimension(s), %d excluded for insufficient data\n",
		rpt.FleetScore.SampleSize, rpt.FleetScore.Dimensions, rpt.FleetScore.ExcludedClusters)
	fmt.Fprintf(&b, "Findings:      %d total (%d critical, %d warning)\n",
		len(rpt.Findings), rpt.Summary.CriticalCount, rpt.Summary.WarningCount)
	fmt.Fprintf(&b, "Sealed:        %t\n", opts.Sealed)
	fmt.Fprintf(&b, "\nContents:\n")
	fmt.Fprintf(&b, "  report.json           Full JSON report (compact)\n")
	fmt.Fprintf(&b, "  report.pretty.json    Same content, indented for human reading\n")
	fmt.Fprintf(&b, "  report.html           Self-contained HTML dashboard\n")
	fmt.Fprintf(&b, "  scan_results.json     Raw scanner results the report was built from\n")
	fmt.Fprintf(&b, "  policyreports/        wgpolicyk8s.io PolicyReport YAML per cluster\n")
	fmt.Fprintf(&b, "  fleetdrift/           FleetDriftReport YAML per cluster\n")
	if opts.Cost != nil {
		fmt.Fprintf(&b, "  cost.json             Cost correlation\n")
	}
	if opts.Sealed {
		fmt.Fprintf(&b, "  %-21s SHA-256 of every other file\n", ManifestFile)
		fmt.Fprintf(&b, "  %-21s HMAC-SHA256 of %s (run 'fleetsweeper verify')\n", FileName, ManifestFile)
	}
	return []byte(b.String())
}

// SealBundle adds ManifestFile and its signature under FileName to files and returns the
// signature.
func SealBundle(files map[string][]byte, key string) (string, error) {
	manifest := Manifest(files)
	sig, err := Sign(manifest, key)
	if err != nil {
		return "", err
	}
	files[ManifestFile] = manifest
	files[FileName] = []byte(sig + "\n")
	return sig, nil
}

// VerifyBundle checks that FileName is a valid signature of ManifestFile under key, then that
// every file matches the manifest. A bundle without either entry returns ErrUnsealed.
func VerifyBundle(files map[string][]byte, key string) error {
	manifest, okManifest := files[ManifestFile]
	sig, okSig := files[FileName]
	if !okManifest || !okSig {
		return ErrUnsealed
	}
	if err := Verify(manifest, string(sig), key); err != nil {
		return err
	}
	return CheckManifest(manifest, files)
}

// WriteBundle writes files as a gzipped tar with every entry under root, in path order, each
// stamped with modTime truncated to the second. Equal inputs give equal bytes.
func WriteBundle(w io.Writer, root string, files map[string][]byte, modTime time.Time) error {
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	mt := modTime.UTC().Truncate(time.Second)
	for _, name := range names {
		data := files[name]
		hdr := &tar.Header{
			Name:     path.Join(root, name),
			Mode:     0o644,
			Size:     int64(len(data)),
			ModTime:  mt,
			Typeflag: tar.TypeReg,
			Format:   tar.FormatPAX,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("tar header %s: %w", name, err)
		}
		if _, err := tw.Write(data); err != nil {
			return fmt.Errorf("tar write %s: %w", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		return fmt.Errorf("tar close: %w", err)
	}
	if err := gz.Close(); err != nil {
		return fmt.Errorf("gzip close: %w", err)
	}
	return nil
}

// ReadBundle reads a bundle in the layout WriteBundle produces and returns its root directory
// and its files keyed by path relative to that root. Entries outside a single root, entries
// that are not regular files, paths that climb with "..", and duplicate paths are errors, so
// nothing in the archive can hide from verification.
func ReadBundle(r io.Reader) (string, map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return "", nil, fmt.Errorf("%w: gzip: %w", ErrBundle, err)
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, maxBundleBytes))

	root := ""
	files := make(map[string][]byte)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", nil, fmt.Errorf("%w: tar: %w", ErrBundle, err)
		}
		if hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return "", nil, fmt.Errorf("%w: %s is not a regular file", ErrBundle, hdr.Name)
		}
		clean := path.Clean(hdr.Name)
		if clean != hdr.Name || path.IsAbs(clean) || strings.HasPrefix(clean, "../") || clean == ".." {
			return "", nil, fmt.Errorf("%w: unsafe path %q", ErrBundle, hdr.Name)
		}
		top, rel, ok := strings.Cut(clean, "/")
		if !ok {
			return "", nil, fmt.Errorf("%w: %s is outside the bundle root", ErrBundle, hdr.Name)
		}
		if root == "" {
			root = top
		} else if top != root {
			return "", nil, fmt.Errorf("%w: entries under both %s and %s", ErrBundle, root, top)
		}
		if _, dup := files[rel]; dup {
			return "", nil, fmt.Errorf("%w: %s appears twice", ErrBundle, rel)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			return "", nil, fmt.Errorf("%w: read %s: %w", ErrBundle, hdr.Name, err)
		}
		files[rel] = data
	}
	if root == "" {
		return "", nil, fmt.Errorf("%w: no files", ErrBundle)
	}
	return root, files, nil
}
