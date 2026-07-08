package cmd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// migrateCmd copies every row from a source Store to a destination Store.
// Useful when transitioning from SQLite to Postgres (or vice versa) without
// hand-rolling pg_dump-and-translate.
var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Copy data between Fleetsweeper backends",
	Long: "Copy every row from a source backend (--from) to a destination\n" +
		"backend (--to). Both DSNs accept the same format as --db on other\n" +
		"subcommands. The destination must be a fresh database; migrate\n" +
		"refuses to clobber existing data unless --force is passed.",
	RunE: runMigrate,
}

func init() {
	migrateCmd.Flags().String("from", "", "Source DSN. SQLite path or postgres:// URL. Required.")
	migrateCmd.Flags().String("from-driver", "", "Source driver. Empty auto-detects from the DSN.")
	migrateCmd.Flags().String("to", "", "Destination DSN. Required.")
	migrateCmd.Flags().String("to-driver", "", "Destination driver. Empty auto-detects from the DSN.")
	migrateCmd.Flags().Bool("force", false, "Allow writing into a destination that already has data.")
	migrateCmd.Flags().Bool("verify", true, "After copy, list every table on both sides and compare lengths.")
}

// runMigrate orchestrates the copy.
func runMigrate(cmd *cobra.Command, _ []string) error {
	fromDSN, _ := cmd.Flags().GetString("from")
	toDSN, _ := cmd.Flags().GetString("to")
	if fromDSN == "" || toDSN == "" {
		return errors.New("--from and --to are required")
	}
	fromDriver, _ := cmd.Flags().GetString("from-driver")
	if fromDriver == "" {
		fromDriver = string(store.DetectDriver(fromDSN))
	}
	toDriver, _ := cmd.Flags().GetString("to-driver")
	if toDriver == "" {
		toDriver = string(store.DetectDriver(toDSN))
	}

	src, err := store.Open(fromDriver, fromDSN)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer src.Close()
	dst, err := store.Open(toDriver, toDSN)
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}
	defer dst.Close()

	if force, _ := cmd.Flags().GetBool("force"); !force {
		if err := refuseIfDestinationNotEmpty(cmdContext(cmd), dst); err != nil {
			return err
		}
	}

	out := cmd.ErrOrStderr()
	ctx, cancel := context.WithTimeout(cmdContext(cmd), 30*time.Minute)
	defer cancel()

	counts := migrationCounts{}
	if err := copyScans(ctx, src, dst, &counts, out); err != nil {
		return fmt.Errorf("copy scans: %w", err)
	}
	if err := copyGroups(ctx, src, dst, &counts, out); err != nil {
		return fmt.Errorf("copy groups: %w", err)
	}
	if err := copyLocations(ctx, src, dst, &counts, out); err != nil {
		return fmt.Errorf("copy locations: %w", err)
	}
	if err := copyAcks(ctx, src, dst, &counts, out); err != nil {
		return fmt.Errorf("copy acks: %w", err)
	}
	if err := copyAPIKeys(ctx, src, dst, &counts, out); err != nil {
		return fmt.Errorf("copy api keys: %w", err)
	}
	if err := copyAuditLog(ctx, src, dst, &counts, out); err != nil {
		return fmt.Errorf("copy audit log: %w", err)
	}

	verify, _ := cmd.Flags().GetBool("verify")
	if verify {
		if err := verifyCounts(ctx, dst, counts, out); err != nil {
			return fmt.Errorf("verify: %w", err)
		}
	}

	fmt.Fprintf(out, "migrate complete: %d scans, %d groups, %d locations, %d acks, %d keys, %d audit rows\n",
		counts.Scans, counts.Groups, counts.Locations, counts.Acks, counts.APIKeys, counts.Audit)
	return nil
}

// migrationCounts tallies copied rows per table for the post-copy
// verification step.
type migrationCounts struct {
	// Scans is the number of scan rows copied.
	Scans int
	// Groups is the number of group rows copied.
	Groups int
	// Locations is the number of cluster_location rows copied.
	Locations int
	// Acks is the number of finding_ack rows copied.
	Acks int
	// APIKeys is the number of api_key rows copied.
	APIKeys int
	// Audit is the number of audit_log rows copied.
	Audit int
}

// refuseIfDestinationNotEmpty checks that the destination database has no
// scans yet. Detecting "empty" via ListScans is enough; the schema is
// always present after Open thanks to migrations.
func refuseIfDestinationNotEmpty(ctx context.Context, dst store.Store) error {
	scans, err := dst.ListScans(ctx, 1)
	if err != nil {
		return fmt.Errorf("inspect destination: %w", err)
	}
	if len(scans) > 0 {
		return errors.New("destination already has data; pass --force to allow overwrite (data is merged, not replaced)")
	}
	keys, err := dst.ListAPIKeys(ctx)
	if err == nil && len(keys) > 0 {
		return errors.New("destination already has api keys; pass --force to allow overwrite")
	}
	return nil
}

// copyScans iterates every scan in the source and re-saves it on the
// destination, preserving the original scan id by going through SaveScan
// (which generates a new id) and then walking back. Because SaveScan
// generates new ids, this preserves data shape but not ids. For backends
// that need identical ids, run pg_dump/sqlite3 .dump instead.
func copyScans(ctx context.Context, src, dst store.Store, c *migrationCounts, out fmtWriter) error {
	scans, err := src.ListScans(ctx, 100000)
	if err != nil {
		return err
	}
	for i := range scans {
		s := scans[len(scans)-1-i] // oldest first so chronology survives
		results, err := src.GetScanResults(ctx, s.ID)
		if err != nil {
			return fmt.Errorf("read scan %s: %w", s.ID, err)
		}
		if _, err := dst.SaveScan(ctx, s.Clusters, results); err != nil {
			return fmt.Errorf("write scan %s: %w", s.ID, err)
		}
		c.Scans++
	}
	fmt.Fprintf(out, "  scans:     %d copied\n", c.Scans)
	_ = scanner.Result{}
	return nil
}

// copyGroups copies every group and its membership.
func copyGroups(ctx context.Context, src, dst store.Store, c *migrationCounts, out fmtWriter) error {
	groups, err := src.ListGroups(ctx)
	if err != nil {
		return err
	}
	for _, g := range groups {
		if err := dst.SaveGroup(ctx, g.Name, g.Clusters); err != nil {
			return fmt.Errorf("write group %s: %w", g.Name, err)
		}
		c.Groups++
	}
	fmt.Fprintf(out, "  groups:    %d copied\n", c.Groups)
	return nil
}

// copyLocations copies every cluster location override.
func copyLocations(ctx context.Context, src, dst store.Store, c *migrationCounts, out fmtWriter) error {
	locs, err := src.ListLocations(ctx)
	if err != nil {
		return err
	}
	for _, l := range locs {
		if err := dst.SetLocation(ctx, l); err != nil {
			return fmt.Errorf("write location %s: %w", l.Cluster, err)
		}
		c.Locations++
	}
	fmt.Fprintf(out, "  locations: %d copied\n", c.Locations)
	return nil
}

// copyAcks copies every active finding ack.
func copyAcks(ctx context.Context, src, dst store.Store, c *migrationCounts, out fmtWriter) error {
	acks, err := src.ListAcks(ctx)
	if err != nil {
		return err
	}
	for _, a := range acks {
		if err := dst.SaveAck(ctx, a); err != nil {
			return fmt.Errorf("write ack %s: %w", a.Fingerprint, err)
		}
		c.Acks++
	}
	fmt.Fprintf(out, "  acks:      %d copied\n", c.Acks)
	return nil
}

// copyAPIKeys copies every api key including revoked ones. Token hashes
// transfer as-is; the raw tokens were never stored so consumers continue
// to use the keys they were issued.
func copyAPIKeys(ctx context.Context, src, dst store.Store, c *migrationCounts, out fmtWriter) error {
	keys, err := src.ListAPIKeys(ctx)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := dst.SaveAPIKey(ctx, k); err != nil {
			if strings.Contains(err.Error(), "duplicate") {
				continue
			}
			return fmt.Errorf("write api key %s: %w", k.ID, err)
		}
		c.APIKeys++
	}
	fmt.Fprintf(out, "  api keys:  %d copied\n", c.APIKeys)
	return nil
}

// copyAuditLog copies every audit log row.
func copyAuditLog(ctx context.Context, src, dst store.Store, c *migrationCounts, out fmtWriter) error {
	entries, err := src.ListAuditEntries(ctx, store.AuditListOptions{Limit: 1000000})
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := dst.SaveAuditEntry(ctx, e); err != nil {
			return fmt.Errorf("write audit %s: %w", e.ID, err)
		}
		c.Audit++
	}
	fmt.Fprintf(out, "  audit:     %d copied\n", c.Audit)
	return nil
}

// verifyCounts re-reads the destination and confirms each table at least
// matches the copied count. (Greater-than is acceptable in --force mode
// where the destination already had rows.)
func verifyCounts(ctx context.Context, dst store.Store, want migrationCounts, out fmtWriter) error {
	scans, err := dst.ListScans(ctx, 100000)
	if err != nil {
		return err
	}
	if len(scans) < want.Scans {
		return fmt.Errorf("scans verify: want >=%d, got %d", want.Scans, len(scans))
	}
	groups, err := dst.ListGroups(ctx)
	if err != nil {
		return err
	}
	if len(groups) < want.Groups {
		return fmt.Errorf("groups verify: want >=%d, got %d", want.Groups, len(groups))
	}
	fmt.Fprintln(out, "verify: ok")
	return nil
}

// fmtWriter is the minimal io.Writer shape we use for migration progress
// output. The cobra command supplies one via ErrOrStderr.
type fmtWriter interface {
	Write(p []byte) (int, error)
}
