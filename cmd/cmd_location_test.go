package cmd

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// newLocationCmd returns a store-bound command with the location set flags.
func newLocationCmd(dbPath string, lat, lng float64, site, notes string) *cobra.Command {
	cmd := newStoreCmd(dbPath)
	cmd.Flags().Float64("lat", lat, "")
	cmd.Flags().Float64("lng", lng, "")
	cmd.Flags().String("site", site, "")
	cmd.Flags().String("notes", notes, "")
	return cmd
}

// TestLocationSetListDelete exercises the full override lifecycle.
func TestLocationSetListDelete(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "loc.db")
	if s, err := store.NewSQLite(dbPath); err != nil {
		t.Fatalf("open: %v", err)
	} else {
		s.Close()
	}
	ctx := context.Background()

	if err := runLocationSet(newLocationCmd(dbPath, 40.7, -74.0, "Store #42", "note"), []string{"edge-1"}); err != nil {
		t.Fatalf("set: %v", err)
	}
	s, _ := store.NewSQLite(dbPath)
	loc, err := s.GetLocation(ctx, "edge-1")
	if err != nil || loc == nil {
		t.Fatalf("get location: %v", err)
	}
	if loc.Site != "Store #42" || loc.Lat != 40.7 {
		t.Errorf("stored location: %+v", loc)
	}
	s.Close()

	if err := runLocationList(newLocationCmd(dbPath, 0, 0, "", ""), nil); err != nil {
		t.Fatalf("list: %v", err)
	}

	if err := runLocationDelete(newLocationCmd(dbPath, 0, 0, "", ""), []string{"edge-1"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	s, _ = store.NewSQLite(dbPath)
	defer s.Close()
	if got, _ := s.GetLocation(ctx, "edge-1"); got != nil {
		t.Errorf("expected nil after delete, got %+v", got)
	}
}

// TestLocationSetValidation verifies out-of-range latitude and longitude are
// rejected before any store write.
func TestLocationSetValidation(t *testing.T) {
	t.Parallel()
	dbPath := filepath.Join(t.TempDir(), "loc.db")
	if s, err := store.NewSQLite(dbPath); err == nil {
		s.Close()
	}
	if err := runLocationSet(newLocationCmd(dbPath, 100, 0, "", ""), []string{"x"}); err == nil {
		t.Error("expected error for latitude > 90")
	}
	if err := runLocationSet(newLocationCmd(dbPath, 0, 200, "", ""), []string{"x"}); err == nil {
		t.Error("expected error for longitude > 180")
	}
}

// TestLocationRequiresDB verifies the missing-db sentinel from a location run.
func TestLocationRequiresDB(t *testing.T) {
	t.Parallel()
	if err := runLocationList(newLocationCmd("", 0, 0, "", ""), nil); !errors.Is(err, ErrNoDatabase) {
		t.Errorf("want ErrNoDatabase, got %v", err)
	}
}
