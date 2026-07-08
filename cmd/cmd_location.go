package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/jsonutil"
	"github.com/dcadolph/fleetsweeper/internal/store"
)

// locationCmd is the parent command for cluster location overrides.
var locationCmd = &cobra.Command{
	Use:   "location",
	Short: "Manage manual geographic location overrides for clusters",
	Long:  "Set, list, and delete manual lat/lng overrides for clusters that do not report a cloud region (retail stores, factories, edge devices).",
}

// locationSetCmd creates or updates a single override.
var locationSetCmd = &cobra.Command{
	Use:   "set <cluster>",
	Short: "Set the manual location for a cluster",
	Args:  cobra.ExactArgs(1),
	RunE:  runLocationSet,
}

// locationListCmd lists every override.
var locationListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all manual location overrides",
	RunE:  runLocationList,
}

// locationDeleteCmd removes a single override.
var locationDeleteCmd = &cobra.Command{
	Use:   "delete <cluster>",
	Short: "Delete the manual location for a cluster",
	Args:  cobra.ExactArgs(1),
	RunE:  runLocationDelete,
}

func init() {
	locationSetCmd.Flags().Float64("lat", 0, "Latitude in degrees north (-90 to 90).")
	locationSetCmd.Flags().Float64("lng", 0, "Longitude in degrees east (-180 to 180).")
	locationSetCmd.Flags().String("site", "", "Human-readable site label, for example \"Store #42, Manhattan\".")
	locationSetCmd.Flags().String("notes", "", "Free-form notes.")
	_ = locationSetCmd.MarkFlagRequired("lat")
	_ = locationSetCmd.MarkFlagRequired("lng")

	locationCmd.AddCommand(locationSetCmd)
	locationCmd.AddCommand(locationListCmd)
	locationCmd.AddCommand(locationDeleteCmd)
}

// runLocationSet writes a single location override.
func runLocationSet(cmd *cobra.Command, args []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	lat, _ := cmd.Flags().GetFloat64("lat")
	lng, _ := cmd.Flags().GetFloat64("lng")
	site, _ := cmd.Flags().GetString("site")
	notes, _ := cmd.Flags().GetString("notes")
	if lat < -90 || lat > 90 {
		return fmt.Errorf("lat must be between -90 and 90, got %g", lat)
	}
	if lng < -180 || lng > 180 {
		return fmt.Errorf("lng must be between -180 and 180, got %g", lng)
	}
	if err := s.SetLocation(cmdContext(cmd), store.LocationRecord{
		Cluster: args[0],
		Lat:     lat,
		Lng:     lng,
		Site:    site,
		Notes:   notes,
	}); err != nil {
		return fmt.Errorf("set location: %w", err)
	}
	fmt.Fprintf(os.Stderr, "saved %s -> (%.4f, %.4f) %s\n", args[0], lat, lng, site)
	return nil
}

// runLocationList prints every override as JSON.
func runLocationList(cmd *cobra.Command, _ []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	pretty, _ := cmd.Flags().GetBool("pretty")
	list, err := s.ListLocations(cmdContext(cmd))
	if err != nil {
		return fmt.Errorf("list locations: %w", err)
	}
	out, err := jsonutil.Marshal(list, pretty)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(out))
	return nil
}

// runLocationDelete removes a single override.
func runLocationDelete(cmd *cobra.Command, args []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()
	if err := s.DeleteLocation(cmdContext(cmd), args[0]); err != nil {
		return fmt.Errorf("delete location: %w", err)
	}
	fmt.Fprintf(os.Stderr, "deleted location for %s\n", args[0])
	return nil
}
