package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/jsonutil"
)

var groupCmd = &cobra.Command{
	Use:   "group",
	Short: "Manage cluster groups",
	Long:  "Create, list, and manage named groups of clusters for targeted scanning and comparison.",
}

var groupCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a cluster group",
	Args:  cobra.ExactArgs(1),
	RunE:  runGroupCreate,
}

var groupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all groups",
	RunE:  runGroupList,
}

var groupDeleteCmd = &cobra.Command{
	Use:   "delete <name>",
	Short: "Delete a group",
	Args:  cobra.ExactArgs(1),
	RunE:  runGroupDelete,
}

var groupAddClusterCmd = &cobra.Command{
	Use:   "add-cluster <group>",
	Short: "Add clusters to a group",
	Args:  cobra.ExactArgs(1),
	RunE:  runGroupAddCluster,
}

var groupRemoveClusterCmd = &cobra.Command{
	Use:   "remove-cluster <group>",
	Short: "Remove clusters from a group",
	Args:  cobra.ExactArgs(1),
	RunE:  runGroupRemoveCluster,
}

func init() {
	groupCreateCmd.Flags().StringSlice("clusters", nil, "Cluster context names to include.")
	groupAddClusterCmd.Flags().StringSlice("clusters", nil, "Cluster context names to add.")
	groupRemoveClusterCmd.Flags().StringSlice("clusters", nil, "Cluster context names to remove.")

	groupCmd.AddCommand(groupCreateCmd)
	groupCmd.AddCommand(groupListCmd)
	groupCmd.AddCommand(groupDeleteCmd)
	groupCmd.AddCommand(groupAddClusterCmd)
	groupCmd.AddCommand(groupRemoveClusterCmd)
}

// runGroupCreate creates a new cluster group.
func runGroupCreate(cmd *cobra.Command, args []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	clusters, _ := cmd.Flags().GetStringSlice("clusters")
	if err := s.SaveGroup(cmd.Context(), args[0], clusters); err != nil {
		return fmt.Errorf("create group: %w", err)
	}
	fmt.Fprintf(os.Stderr, "group %q created with %d cluster(s)\n", args[0], len(clusters))
	return nil
}

// runGroupList lists all groups.
func runGroupList(cmd *cobra.Command, _ []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	pretty, _ := cmd.Flags().GetBool("pretty")
	groups, err := s.ListGroups(cmd.Context())
	if err != nil {
		return fmt.Errorf("list groups: %w", err)
	}

	out, err := jsonutil.Marshal(groups, pretty)
	if err != nil {
		return fmt.Errorf("marshal groups: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(out))
	return nil
}

// runGroupDelete deletes a group.
func runGroupDelete(cmd *cobra.Command, args []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.DeleteGroup(cmd.Context(), args[0]); err != nil {
		return fmt.Errorf("delete group: %w", err)
	}
	fmt.Fprintf(os.Stderr, "group %q deleted\n", args[0])
	return nil
}

// runGroupAddCluster adds clusters to an existing group.
func runGroupAddCluster(cmd *cobra.Command, args []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	clusters, _ := cmd.Flags().GetStringSlice("clusters")
	ctx := cmd.Context()
	for _, c := range clusters {
		if err := s.AddClusterToGroup(ctx, args[0], c); err != nil {
			return fmt.Errorf("add cluster %s: %w", c, err)
		}
	}
	fmt.Fprintf(os.Stderr, "added %d cluster(s) to group %q\n", len(clusters), args[0])
	return nil
}

// runGroupRemoveCluster removes clusters from a group.
func runGroupRemoveCluster(cmd *cobra.Command, args []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	clusters, _ := cmd.Flags().GetStringSlice("clusters")
	ctx := cmd.Context()
	for _, c := range clusters {
		if err := s.RemoveClusterFromGroup(ctx, args[0], c); err != nil {
			return fmt.Errorf("remove cluster %s: %w", c, err)
		}
	}
	fmt.Fprintf(os.Stderr, "removed %d cluster(s) from group %q\n", len(clusters), args[0])
	return nil
}
