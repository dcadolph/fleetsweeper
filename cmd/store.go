package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/server"
	"github.com/dcadolph/fleetsweeper/internal/store"
	"github.com/dcadolph/fleetsweeper/internal/util"
)

// openAnyStore opens whichever backend the --db / --db-driver flag pair points at, or the default
// state store when --db is empty. Returns the broader Store interface so callers can use either
// backend transparently.
func openAnyStore(cmd *cobra.Command) (store.Store, error) {
	dbPath, err := resolveDBPath(cmd)
	if err != nil {
		return nil, err
	}
	return openStorePath(cmd, dbPath)
}

// openStorePath opens the store at dbPath with the driver --db-driver names, or the one its
// prefix implies.
func openStorePath(cmd *cobra.Command, dbPath string) (store.Store, error) {
	driver, _ := cmd.Flags().GetString("db-driver")
	if driver == "" {
		driver = string(store.DetectDriver(dbPath))
	}
	return store.Open(driver, dbPath)
}

// resolveDBPath returns --db, or the default state store when --db is empty. The default store's
// directory is created 0700 and its file 0600, and the first use prints the path to stderr once so
// the user learns where history lives without having chosen it.
func resolveDBPath(cmd *cobra.Command) (string, error) {
	if dbPath, _ := cmd.Flags().GetString("db"); dbPath != "" {
		return dbPath, nil
	}
	path, err := util.DefaultStatePath()
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrNoDatabase, err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("create state dir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	switch {
	case err == nil:
		if err := f.Close(); err != nil {
			return "", fmt.Errorf("create store %s: %w", path, err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Storing scans in %s. Pass --db to use another store.\n", path)
	case !errors.Is(err, fs.ErrExist):
		return "", fmt.Errorf("create store %s: %w", path, err)
	}
	return path, nil
}

// existingDBPath returns --db, or the default state store when --db is empty and that store
// already exists. It creates nothing, so a read-only check never leaves a store behind.
func existingDBPath(cmd *cobra.Command) (string, bool) {
	if dbPath, _ := cmd.Flags().GetString("db"); dbPath != "" {
		return dbPath, true
	}
	path, err := util.DefaultStatePath()
	if err != nil {
		return "", false
	}
	if _, err := os.Stat(path); err != nil {
		return path, false
	}
	return path, true
}

// resolveScanRef maps a scan reference to a stored scan ID. It accepts latest, previous or
// second-latest, and returns any other ref unchanged as a scan ID.
func resolveScanRef(ctx context.Context, st store.Store, ref string) (string, error) {
	var idx int
	switch ref {
	case "latest":
	case "previous", "second-latest":
		idx = 1
	default:
		return ref, nil
	}
	scans, err := st.ListScans(ctx, idx+1)
	if err != nil {
		return "", fmt.Errorf("resolve %q: list scans: %w", ref, err)
	}
	switch {
	case len(scans) == 0:
		return "", ErrNoScans
	case len(scans) <= idx:
		return "", fmt.Errorf("%w: %q found %d", ErrTooFewScans, ref, len(scans))
	}
	return scans[idx].ID, nil
}

// storedScan is a scan read back from the store with everything its report is built from.
type storedScan struct {
	// Record is the stored scan row.
	Record *store.ScanRecord
	// Results holds the raw scanner results keyed by cluster, then scanner.
	Results map[string]map[string]scanner.Result
	// Opts carries the store's cohort tags and groups and the scan's timestamp.
	Opts report.BuildOptions
}

// Report rebuilds the scan's report.
func (s *storedScan) Report() *report.Report {
	return report.Build(s.Record.Clusters, s.Results, s.Opts)
}

// loadStoredScan reads a scan, its results, and the store's cohort tags and groups, so a
// report rebuilt from it partitions cohorts the way the server does for the same scan.
func loadStoredScan(ctx context.Context, st store.Store, id string) (*storedScan, error) {
	rec, err := st.GetScan(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get scan %s: %w", id, err)
	}
	results, err := st.GetScanResults(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get scan results %s: %w", id, err)
	}
	opts, err := server.StoreReportOptions(ctx, st)
	if err != nil {
		return nil, fmt.Errorf("load report options: %w", err)
	}
	opts.Timestamp = rec.Timestamp
	return &storedScan{Record: rec, Results: results, Opts: opts}, nil
}

// loadStoredReport reads a stored scan and rebuilds its report with the store's cohort tags
// and groups.
func loadStoredReport(ctx context.Context, st store.Store, id string) (*report.Report, *store.ScanRecord, error) {
	sc, err := loadStoredScan(ctx, st, id)
	if err != nil {
		return nil, nil, err
	}
	return sc.Report(), sc.Record, nil
}
