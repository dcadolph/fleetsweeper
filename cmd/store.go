package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/report"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/server"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// openAnyStore opens whichever backend the --db / --db-driver flag pair points
// at. Returns the broader Store interface so callers can use either backend
// transparently.
func openAnyStore(cmd *cobra.Command) (store.Store, error) {
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath == "" {
		return nil, ErrNoDatabase
	}
	driver, _ := cmd.Flags().GetString("db-driver")
	if driver == "" {
		driver = string(store.DetectDriver(dbPath))
	}
	return store.Open(driver, dbPath)
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
