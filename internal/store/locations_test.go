package store

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// TestLocationSetGetDelete verifies the manual location override lifecycle:
// insert, read back with every field, upsert in place, and delete.
func TestLocationSetGetDelete(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	loc := LocationRecord{
		Cluster: "store-42",
		Lat:     40.7128,
		Lng:     -74.0060,
		Site:    "Store #42, Manhattan",
		Notes:   "flagship",
	}
	if err := s.SetLocation(ctx, loc); err != nil {
		t.Fatalf("set: %v", err)
	}

	got, err := s.GetLocation(ctx, "store-42")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("expected a record, got nil")
	}
	if got.Lat != loc.Lat || got.Lng != loc.Lng || got.Site != loc.Site || got.Notes != loc.Notes {
		t.Errorf("fields not preserved: %+v", got)
	}
	if got.UpdatedAt.IsZero() {
		t.Error("expected UpdatedAt to be set")
	}

	// Upsert overwrites the coordinates in place.
	loc.Lat, loc.Lng, loc.Site = 51.5074, -0.1278, "Store #7, London"
	if err := s.SetLocation(ctx, loc); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = s.GetLocation(ctx, "store-42")
	if got.Lat != 51.5074 || got.Site != "Store #7, London" {
		t.Errorf("upsert did not overwrite: %+v", got)
	}

	// Delete removes the override.
	if err := s.DeleteLocation(ctx, "store-42"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	got, err = s.GetLocation(ctx, "store-42")
	if err != nil {
		t.Fatalf("get after delete: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil after delete, got %+v", got)
	}
}

// TestGetLocationNotSet verifies a cluster with no override returns nil without
// an error.
func TestGetLocationNotSet(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	got, err := s.GetLocation(context.Background(), "unknown")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

// TestListLocationsSorted verifies every override is returned ordered by
// cluster name.
func TestListLocationsSorted(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	ctx := context.Background()

	_ = s.SetLocation(ctx, LocationRecord{Cluster: "west", Lat: 1, Lng: 2})
	_ = s.SetLocation(ctx, LocationRecord{Cluster: "east", Lat: 3, Lng: 4})
	_ = s.SetLocation(ctx, LocationRecord{Cluster: "central", Lat: 5, Lng: 6})

	got, err := s.ListLocations(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var names []string
	for _, l := range got {
		names = append(names, l.Cluster)
	}
	if diff := cmp.Diff([]string{"central", "east", "west"}, names); diff != "" {
		t.Errorf("order (-want +got):\n%s", diff)
	}
}

// TestListLocationsEmpty verifies an empty database yields no locations.
func TestListLocationsEmpty(t *testing.T) {
	t.Parallel()
	s := newTestSQLite(t)
	got, err := s.ListLocations(context.Background())
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no locations, got %d", len(got))
	}
}
