package cmd

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// backupCmd snapshots the configured SQLite database to a file. Postgres
// users should rely on their database's native pg_dump tooling.
var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Snapshot the SQLite database to a portable file",
	Long: "Use SQLite's online VACUUM INTO to write a consistent snapshot of\n" +
		"the database referenced by --db. Pass --output to choose the file path;\n" +
		"append .gz to enable gzip compression. Postgres backends should use\n" +
		"pg_dump or the database provider's native snapshot tooling instead.",
	RunE: runBackup,
}

// restoreCmd writes a previously-captured snapshot back into the --db file.
var restoreCmd = &cobra.Command{
	Use:   "restore <snapshot>",
	Short: "Restore a SQLite snapshot taken by `fleetsweeper backup`",
	Long: "Copy the snapshot file at the given path into --db, overwriting it\n" +
		"only when --force is passed. The restored database is opened and migrated\n" +
		"to the latest schema before the command returns.",
	Args: cobra.ExactArgs(1),
	RunE: runRestore,
}

func init() {
	backupCmd.Flags().String("output", "", "Output path. Use .gz suffix to enable gzip compression.")
	backupCmd.Flags().Bool("overwrite", false, "Overwrite the output file when it already exists.")
	restoreCmd.Flags().Bool("force", false, "Overwrite the existing --db file. Required when --db points at an existing database.")
}

// runBackup captures a consistent SQLite snapshot.
func runBackup(cmd *cobra.Command, _ []string) error {
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath == "" {
		return ErrNoDatabase
	}
	driver, _ := cmd.Flags().GetString("db-driver")
	if driver == "" {
		driver = string(store.DetectDriver(dbPath))
	}
	if driver != string(store.DriverSQLite) {
		return fmt.Errorf("backup: only the sqlite driver is supported; use pg_dump for postgres")
	}

	output, _ := cmd.Flags().GetString("output")
	if output == "" {
		return fmt.Errorf("--output is required")
	}
	overwrite, _ := cmd.Flags().GetBool("overwrite")
	if _, err := os.Stat(output); err == nil && !overwrite {
		return fmt.Errorf("output %q exists; pass --overwrite to replace", output)
	}

	gzipped := strings.HasSuffix(strings.ToLower(output), ".gz")
	tmpDir, err := os.MkdirTemp("", "fleetsweeper-backup-*")
	if err != nil {
		return fmt.Errorf("temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	snapshotPath := filepath.Join(tmpDir, "snapshot.db")

	src, err := store.NewSQLite(dbPath)
	if err != nil {
		return fmt.Errorf("open source database: %w", err)
	}
	defer src.Close()

	if err := src.VacuumInto(context.Background(), snapshotPath); err != nil {
		return fmt.Errorf("snapshot: %w", err)
	}

	dst, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	defer dst.Close()

	var writer io.Writer = dst
	if gzipped {
		gz := gzip.NewWriter(dst)
		defer gz.Close()
		writer = gz
	}

	in, err := os.Open(snapshotPath)
	if err != nil {
		return fmt.Errorf("open snapshot: %w", err)
	}
	defer in.Close()
	if _, err := io.Copy(writer, in); err != nil {
		return fmt.Errorf("copy snapshot: %w", err)
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "backup written to %s\n", output)
	return nil
}

// runRestore copies a snapshot file into the --db path and verifies the
// schema migrates cleanly.
func runRestore(cmd *cobra.Command, args []string) error {
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath == "" {
		return ErrNoDatabase
	}
	driver, _ := cmd.Flags().GetString("db-driver")
	if driver == "" {
		driver = string(store.DetectDriver(dbPath))
	}
	if driver != string(store.DriverSQLite) {
		return fmt.Errorf("restore: only the sqlite driver is supported; use pg_restore for postgres")
	}

	src := args[0]
	if _, err := os.Stat(src); err != nil {
		return fmt.Errorf("snapshot %q: %w", src, err)
	}
	force, _ := cmd.Flags().GetBool("force")
	if _, err := os.Stat(dbPath); err == nil && !force {
		return fmt.Errorf("%q exists; pass --force to overwrite", dbPath)
	}

	if err := copyMaybeGz(src, dbPath); err != nil {
		return fmt.Errorf("copy snapshot: %w", err)
	}

	// Open and migrate to confirm the snapshot is usable with this binary.
	s, err := store.NewSQLite(dbPath)
	if err != nil {
		return fmt.Errorf("open restored database: %w", err)
	}
	defer s.Close()

	fmt.Fprintf(cmd.ErrOrStderr(), "restored %s -> %s\n", src, dbPath)
	return nil
}

// copyMaybeGz copies src to dst, decompressing on the fly when src ends in .gz.
func copyMaybeGz(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	var reader io.Reader = in
	if strings.HasSuffix(strings.ToLower(src), ".gz") {
		gz, err := gzip.NewReader(in)
		if err != nil {
			return fmt.Errorf("gzip: %w", err)
		}
		defer gz.Close()
		reader = gz
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, reader); err != nil {
		return err
	}
	return nil
}
