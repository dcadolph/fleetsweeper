package cmd

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/seal"
)

// verifyCmd checks that every file in an export bundle still matches the signed MANIFEST
// produced at export time. Intended for audit and compliance workflows where a bundle handed
// over weeks ago must be proven untampered before being acted on.
var verifyCmd = &cobra.Command{
	Use:   "verify <bundle.tar.gz>",
	Short: "Verify the HMAC seal of a fleetsweeper export bundle",
	Long: "Read a .tar.gz produced by 'fleetsweeper export --seal-key', confirm that " +
		"MANIFEST.sig is a valid signature of MANIFEST, and check every file in the " +
		"bundle against the SHA-256 the MANIFEST lists for it. A missing, altered, or " +
		"unlisted file fails verification. Exits 0 when the seal is valid, non-zero on " +
		"tampering, missing signature, or wrong key. The seal secret may be passed via " +
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

	_, files, err := seal.ReadBundle(f)
	if err != nil {
		return fmt.Errorf("read bundle: %w", err)
	}
	if err := seal.VerifyBundle(files, sealKey); err != nil {
		switch {
		case errors.Is(err, seal.ErrUnsealed):
			fmt.Fprintf(cmd.ErrOrStderr(), "verify: bundle has no %s or %s; export with --seal-key to enable verification\n",
				seal.ManifestFile, seal.FileName)
		case errors.Is(err, seal.ErrMismatch):
			fmt.Fprintln(cmd.ErrOrStderr(), "verify: signature mismatch (manifest was tampered with or wrong key)")
		case errors.Is(err, seal.ErrMalformed):
			fmt.Fprintln(cmd.ErrOrStderr(), "verify: signature file is malformed")
		case errors.Is(err, seal.ErrContents), errors.Is(err, seal.ErrManifest):
			fmt.Fprintf(cmd.ErrOrStderr(), "verify: %v\n", err)
		}
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "ok: signature matches %s and all %d files match it\n",
		seal.ManifestFile, len(files)-2)
	return nil
}
