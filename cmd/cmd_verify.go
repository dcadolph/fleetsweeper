package cmd

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/seal"
)

// verifyCmd checks that the report.json inside an export bundle still
// matches the report.sig that was produced at export time. Intended for
// audit and compliance workflows where a bundle handed over weeks ago
// must be proven untampered before being acted on.
var verifyCmd = &cobra.Command{
	Use:   "verify <bundle.tar.gz>",
	Short: "Verify the HMAC seal of a fleetsweeper export bundle",
	Long: "Read a .tar.gz produced by 'fleetsweeper export --seal-key' and " +
		"confirm that report.json matches the signature in report.sig. " +
		"Exits 0 when the seal is valid, non-zero on tampering, missing " +
		"signature, or wrong key. The seal secret may be passed via " +
		"--seal-key or the FLEETSWEEPER_SEAL_KEY environment variable.",
	Args: cobra.ExactArgs(1),
	RunE: runVerify,
}

func init() {
	verifyCmd.Flags().String("seal-key", "", "HMAC-SHA256 secret used to sign the bundle.")
}

// runVerify is the cobra entrypoint for the verify subcommand.
func runVerify(cmd *cobra.Command, args []string) error {
	bundlePath := args[0]
	sealKey, _ := cmd.Flags().GetString("seal-key")
	if sealKey == "" {
		sealKey = os.Getenv("FLEETSWEEPER_SEAL_KEY")
	}
	if sealKey == "" {
		return fmt.Errorf("--seal-key is required (or set FLEETSWEEPER_SEAL_KEY)")
	}

	f, err := os.Open(bundlePath)
	if err != nil {
		return fmt.Errorf("open bundle: %w", err)
	}
	defer f.Close()

	reportBytes, signature, err := readSealedBundle(f)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	if signature == "" {
		return fmt.Errorf("bundle does not contain %s; export with --seal-key to enable verification", seal.FileName)
	}

	if err := seal.Verify(reportBytes, signature, sealKey); err != nil {
		switch {
		case errors.Is(err, seal.ErrMismatch):
			fmt.Fprintln(cmd.ErrOrStderr(), "verify: signature mismatch (bundle was tampered with or wrong key)")
		case errors.Is(err, seal.ErrMalformed):
			fmt.Fprintln(cmd.ErrOrStderr(), "verify: signature file is malformed")
		}
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), "ok: signature matches report.json")
	return nil
}

// readSealedBundle scans the gzipped tar in r and returns the bytes of
// report.json and the trimmed signature string from report.sig. Either
// value may be empty when absent. Other entries are skipped so the caller
// does not have to know the bundle layout.
func readSealedBundle(r io.Reader) ([]byte, string, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, "", fmt.Errorf("gzip: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	var (
		reportBytes []byte
		signature   string
	)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, "", fmt.Errorf("tar: %w", err)
		}
		name := path.Base(hdr.Name)
		switch name {
		case seal.SourceFile:
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, "", fmt.Errorf("read %s: %w", name, err)
			}
			reportBytes = data
		case seal.FileName:
			data, err := io.ReadAll(tr)
			if err != nil {
				return nil, "", fmt.Errorf("read %s: %w", name, err)
			}
			signature = strings.TrimSpace(string(data))
		}
	}
	if reportBytes == nil {
		return nil, "", fmt.Errorf("bundle missing %s", seal.SourceFile)
	}
	return reportBytes, signature, nil
}
