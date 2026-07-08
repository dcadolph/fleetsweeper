package cmd

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

// tagCmd is the parent for cluster-tag operations. Tags are free-form
// (key, value) pairs persisted in the store; the dashboard and `?tag=`
// query filters slice the fleet by them.
var tagCmd = &cobra.Command{
	Use:   "tag",
	Short: "Manage cluster tags (env, tier, owner, ...)",
}

// tagListCmd prints every tag across the fleet.
var tagListCmd = &cobra.Command{
	Use:   "list",
	Short: "List every tag pair across the fleet",
	RunE:  runTagList,
}

// tagSetCmd upserts one or more key=value pairs on a cluster.
var tagSetCmd = &cobra.Command{
	Use:   "set <cluster> <key=value>...",
	Short: "Upsert one or more tags on a cluster",
	Args:  cobra.MinimumNArgs(2),
	RunE:  runTagSet,
}

// tagDelCmd removes one tag key from a cluster.
var tagDelCmd = &cobra.Command{
	Use:   "del <cluster> <key>",
	Short: "Remove one tag key from a cluster",
	Args:  cobra.ExactArgs(2),
	RunE:  runTagDel,
}

func init() {
	tagCmd.AddCommand(tagListCmd)
	tagCmd.AddCommand(tagSetCmd)
	tagCmd.AddCommand(tagDelCmd)
}

// runTagList walks the cluster_tags table and prints a per-cluster
// summary sorted alphabetically.
func runTagList(cmd *cobra.Command, _ []string) error {
	st, err := openAnyStore(cmd)
	if err != nil {
		return err
	}
	defer st.Close()
	all, err := st.ListClusterTags(cmdContext(cmd))
	if err != nil {
		return err
	}
	return writeTagList(cmd.OutOrStdout(), all)
}

// runTagSet parses one cluster name plus N "key=value" pairs and
// upserts each via the Store.
func runTagSet(cmd *cobra.Command, args []string) error {
	cluster := args[0]
	pairs := args[1:]
	st, err := openAnyStore(cmd)
	if err != nil {
		return err
	}
	defer st.Close()

	ctx := cmdContext(cmd)
	for _, p := range pairs {
		k, v, ok := strings.Cut(p, "=")
		if !ok || k == "" {
			return fmt.Errorf("invalid pair %q; want key=value", p)
		}
		if err := st.SetClusterTag(ctx, cluster, k, v); err != nil {
			return fmt.Errorf("set %s/%s: %w", cluster, k, err)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "set %s %s=%s\n", cluster, k, v)
	}
	return nil
}

// runTagDel removes one key from one cluster.
func runTagDel(cmd *cobra.Command, args []string) error {
	st, err := openAnyStore(cmd)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.DeleteClusterTag(cmdContext(cmd), args[0], args[1]); err != nil {
		return err
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "deleted %s %s\n", args[0], args[1])
	return nil
}

// writeTagList prints the tag table.
func writeTagList(w io.Writer, all map[string]map[string]string) error {
	if len(all) == 0 {
		fmt.Fprintln(w, "No cluster tags set.")
		return nil
	}
	clusters := make([]string, 0, len(all))
	for c := range all {
		clusters = append(clusters, c)
	}
	sort.Strings(clusters)
	for _, c := range clusters {
		tags := all[c]
		keys := make([]string, 0, len(tags))
		for k := range tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			parts = append(parts, k+"="+tags[k])
		}
		fmt.Fprintf(w, "%-30s  %s\n", c, strings.Join(parts, "  "))
	}
	return nil
}
