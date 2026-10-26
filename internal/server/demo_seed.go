package server

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// demoScans is how many scans the demo seeds, and demoStep the time between them: six days of
// history at a six-hour cadence.
const (
	demoScans = 24
	demoStep  = 6 * time.Hour
)

// ErrDemoSeed is returned when the demo store cannot be seeded.
var ErrDemoSeed = errors.New("demo seed failed")

// demoScanIDAt returns the ID of demo scan i, oldest first.
func demoScanIDAt(i int) string {
	return fmt.Sprintf("demo-%02d", i+1)
}

// SeedDemo fills an empty store with the demo fleet: a series of scans ending at now whose
// results are built from each scanner's own data types and run through the real engine on read,
// plus inbound alerts, cohort tags, groups, and manual locations. A store that already holds
// scans is left alone.
func SeedDemo(ctx context.Context, st store.Store, now time.Time) error {
	existing, err := st.ListScans(ctx, 1)
	if err != nil {
		return fmt.Errorf("%w: list scans: %w", ErrDemoSeed, err)
	}
	if len(existing) > 0 {
		return nil
	}
	clusters := demoClusterNames()
	for i := range demoScans {
		at := now.Add(-time.Duration(demoScans-1-i) * demoStep)
		rec := store.ScanRecord{ID: demoScanIDAt(i), Timestamp: at, Clusters: clusters}
		if _, err := st.SaveScanRecord(ctx, rec, demoResults(i, demoScans, at, now)); err != nil {
			return fmt.Errorf("%w: save scan %d: %w", ErrDemoSeed, i, err)
		}
	}
	for _, c := range demoFleet() {
		if err := st.SetClusterTag(ctx, c.Name, cohortTagKey, c.Cohort); err != nil {
			return fmt.Errorf("%w: tag %s: %w", ErrDemoSeed, c.Name, err)
		}
		if c.Source != "manual" {
			continue
		}
		loc := store.LocationRecord{Cluster: c.Name, Lat: c.Lat, Lng: c.Lng, Site: c.Site, UpdatedAt: now}
		if err := st.SetLocation(ctx, loc); err != nil {
			return fmt.Errorf("%w: locate %s: %w", ErrDemoSeed, c.Name, err)
		}
	}
	for _, g := range demoGroups() {
		if err := st.SaveGroup(ctx, g.Name, g.Clusters); err != nil {
			return fmt.Errorf("%w: group %s: %w", ErrDemoSeed, g.Name, err)
		}
	}
	for _, a := range demoAlerts(now) {
		if err := st.UpsertAlert(ctx, a); err != nil {
			return fmt.Errorf("%w: alert %s: %w", ErrDemoSeed, a.Fingerprint, err)
		}
	}
	return nil
}
