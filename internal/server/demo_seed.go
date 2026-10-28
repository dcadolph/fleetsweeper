package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
	"github.com/dcadolph/fleetsweeper/internal/scanner/crd"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// demoScans is how many scans the demo seeds, and demoStep the time between them: six days of
// history at a six-hour cadence.
const (
	demoScans = 24
	demoStep  = 6 * time.Hour
)

// demoDriftCluster and demoDriftGroup are the scripted change live demo scans carry: every other
// live scan, prod-eu-central-1 loses the cert-manager CRDs every other cluster runs, and the scan
// after restores them, so a viewer sees a drift land and then clear.
const (
	demoDriftCluster = "prod-eu-central-1"
	demoDriftGroup   = "cert-manager.io"
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
		if _, err := st.SaveScanRecord(ctx, rec, demoResults(i, at, now)); err != nil {
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

// demoLiveScan returns the clusters and results of live demo scan k, the k-th scan triggered
// since startup: the newest seeded state of each requested cluster at now, with the scripted
// drift on even k. Requested names outside the demo fleet are ignored.
func demoLiveScan(k int, requested []string, now time.Time) ([]string, map[string]map[string]scanner.Result) {
	all := demoResults(demoScans-1, now, now)
	if k%2 == 0 {
		if res, ok := all[demoDriftCluster][crd.Name]; ok {
			if d, isCRD := res.Data.(crd.Data); isCRD {
				kept := make([]crd.Info, 0, len(d.CRDs))
				for _, c := range d.CRDs {
					if c.Group != demoDriftGroup {
						kept = append(kept, c)
					}
				}
				d.CRDs, d.Count = kept, len(kept)
				res.Data = d
				all[demoDriftCluster][crd.Name] = res
			}
		}
	}
	clusters := make([]string, 0, len(requested))
	results := make(map[string]map[string]scanner.Result, len(requested))
	for _, c := range demoClusterNames() {
		if r, ok := all[c]; ok && slices.Contains(requested, c) {
			clusters = append(clusters, c)
			results[c] = r
		}
	}
	return clusters, results
}
