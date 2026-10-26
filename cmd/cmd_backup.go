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
		"only when --force is passed. The snapshot is written to a temporary file\n" +
		"beside --db, opened and migrated to the latest schema there, and only then\n" +
		"renamed over --db, so a bad snapshot never replaces a good database. Stale\n" +
		"-wal and -shm files of the old database are removed first. Stop any server\n" +
		"using --db before restoring.",
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

	if err := writeSnapshot(snapshotPath, output, gzipped); err != nil {
		return err
	}

	fmt.Fprintf(cmd.ErrOrStderr(), "backup written to %s\n", output)
	return nil
}

// writeSnapshot copies the snapshot at src to output, gzipping when gzipped is set. Every close
// is checked, so a backup that could not be flushed is an error rather than a truncated file.
func writeSnapshot(src, output string, gzipped bool) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open snapshot: %w", err)
	}
	defer in.Close()
	dst, err := os.Create(output)
	if err != nil {
		return fmt.Errorf("create output: %w", err)
	}
	var writer io.Writer = dst
	var gz *gzip.Writer
	if gzipped {
		gz = gzip.NewWriter(dst)
		writer = gz
	}
	if _, err := io.Copy(writer, in); err != nil {
		_ = dst.Close()
		return fmt.Errorf("copy snapshot: %w", err)
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			_ = dst.Close()
			return fmt.Errorf("gzip close: %w", err)
		}
	}
	if err := dst.Close(); err != nil {
		return fmt.Errorf("close output: %w", err)
	}
	return nil
}

// runRestore writes a snapshot to a temporary file beside the --db path, migrates it there,
// and renames it over --db once it opens cleanly.
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

	if err := restoreSnapshot(src, dbPath); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "restored %s -> %s\n", src, dbPath)
	return nil
}

// restoreSnapshot replaces dbPath with the snapshot at src. The snapshot is copied to a
// temporary file in dbPath's directory and opened there, which runs migrations and proves it is
// a database this binary can use. The temporary file must close without a leftover WAL. Then the
// old database's -wal and -shm files are removed, since SQLite would replay a stale WAL onto the
// new file, and the temporary file is renamed over dbPath. A failure at any step before the
// rename leaves dbPath untouched and removes the temporary file.
func restoreSnapshot(src, dbPath string) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(dbPath), filepath.Base(dbPath)+".restore-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}
	defer func() {
		if err != nil {
			for _, p := range sqliteFiles(tmpPath) {
				_ = os.Remove(p)
			}
		}
	}()

	if err := copyMaybeGz(src, tmpPath); err != nil {
		return fmt.Errorf("copy snapshot: %w", err)
	}
	s, err := store.NewSQLite(tmpPath)
	if err != nil {
		return fmt.Errorf("open snapshot: %w", err)
	}
	if err := s.Close(); err != nil {
		return fmt.Errorf("close snapshot: %w", err)
	}
	if fi, statErr := os.Stat(tmpPath + "-wal"); statErr == nil && fi.Size() > 0 {
		return fmt.Errorf("snapshot left %d bytes of WAL after migration", fi.Size())
	}
	for _, p := range sqliteFiles(tmpPath)[1:] {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove %s: %w", p, err)
		}
	}
	for _, p := range sqliteFiles(dbPath)[1:] {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove stale %s: %w", p, err)
		}
	}
	if err := os.Rename(tmpPath, dbPath); err != nil {
		return fmt.Errorf("rename into place: %w", err)
	}
	return nil
}

// sqliteFiles returns the database file at path followed by its -wal and -shm companions.
func sqliteFiles(path string) []string {
	return []string{path, path + "-wal", path + "-shm"}
}

// copyMaybeGz copies src to dst, decompressing on the fly when src ends in .gz. The copy is
// synced to disk before it returns.
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
	if _, err := io.Copy(out, reader); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Sync(); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}
