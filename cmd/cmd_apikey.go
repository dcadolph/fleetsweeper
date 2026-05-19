package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// apikeyCmd is the parent command for API key management.
// All subcommands operate directly against the configured --db so an operator
// can mint the first admin key before the server is running.
var apikeyCmd = &cobra.Command{
	Use:   "apikey",
	Short: "Manage API keys for the Fleetsweeper server",
	Long: "Create, list, and revoke API keys used to authenticate against the\n" +
		"Fleetsweeper HTTP API. Operates directly on the configured database so\n" +
		"the first admin key can be minted without the server running.",
}

// apikeyCreateCmd mints a new key and prints the raw token to stdout.
var apikeyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Mint a new API key",
	Long: "Create a new API key with the given name, role, and cluster scope.\n" +
		"The raw token is printed exactly once. Save it now; the server stores\n" +
		"only its hash and cannot reveal it again.",
	RunE: runAPIKeyCreate,
}

// apikeyListCmd lists every API key as JSON.
var apikeyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all API keys (token hashes redacted)",
	RunE:  runAPIKeyList,
}

// apikeyRevokeCmd marks an API key as administratively disabled.
var apikeyRevokeCmd = &cobra.Command{
	Use:   "revoke <id>",
	Short: "Revoke an API key by ID",
	Args:  cobra.ExactArgs(1),
	RunE:  runAPIKeyRevoke,
}

func init() {
	apikeyCreateCmd.Flags().String("name", "", "Human-readable key label (required).")
	apikeyCreateCmd.Flags().String("role", "operator", "One of admin, operator, viewer.")
	apikeyCreateCmd.Flags().StringSlice("scope", nil,
		"Cluster scope entries. Repeat for multiple. Use \"*\" for all clusters or \"group:<name>\" for a group. Empty defaults to \"*\".")
	apikeyCreateCmd.Flags().Duration("ttl", 0, "Optional expiry duration (for example 720h for 30 days). 0 means never expires.")

	apikeyCmd.AddCommand(apikeyCreateCmd)
	apikeyCmd.AddCommand(apikeyListCmd)
	apikeyCmd.AddCommand(apikeyRevokeCmd)
}

// runAPIKeyCreate mints a new key. Outputs JSON to stdout containing the raw
// token plus the metadata. The raw token field is the one to capture.
func runAPIKeyCreate(cmd *cobra.Command, _ []string) error {
	name, _ := cmd.Flags().GetString("name")
	role, _ := cmd.Flags().GetString("role")
	scope, _ := cmd.Flags().GetStringSlice("scope")
	ttl, _ := cmd.Flags().GetDuration("ttl")
	pretty, _ := cmd.Flags().GetBool("pretty")

	if name == "" {
		return fmt.Errorf("--name is required")
	}
	if !store.ValidRole(role) {
		return fmt.Errorf("role must be admin, operator, or viewer; got %q", role)
	}
	scope = cleanScope(scope)

	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	raw, err := store.GenerateToken()
	if err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	rec := store.APIKeyRecord{
		ID:           "key_cli_" + time.Now().UTC().Format("20060102T150405Z"),
		TokenHash:    store.HashToken(raw),
		Name:         name,
		Role:         role,
		ClusterScope: scope,
		CreatedAt:    time.Now().UTC(),
		CreatedBy:    "cli",
	}
	if ttl > 0 {
		rec.ExpiresAt = rec.CreatedAt.Add(ttl)
	}

	ctx := context.Background()
	if err := s.SaveAPIKey(ctx, rec); err != nil {
		return fmt.Errorf("save api key: %w", err)
	}

	out := map[string]any{
		"id":            rec.ID,
		"name":          rec.Name,
		"role":          rec.Role,
		"cluster_scope": rec.ClusterScope,
		"created_at":    rec.CreatedAt,
		"expires_at":    rec.ExpiresAt,
		"token":         raw,
	}
	return writeAPIKeyJSON(cmd, out, pretty)
}

// runAPIKeyList prints every API key as a JSON array.
func runAPIKeyList(cmd *cobra.Command, _ []string) error {
	pretty, _ := cmd.Flags().GetBool("pretty")
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	keys, err := s.ListAPIKeys(context.Background())
	if err != nil {
		return fmt.Errorf("list api keys: %w", err)
	}
	out := make([]map[string]any, len(keys))
	for i, k := range keys {
		out[i] = map[string]any{
			"id":            k.ID,
			"name":          k.Name,
			"role":          k.Role,
			"cluster_scope": k.ClusterScope,
			"created_at":    k.CreatedAt,
			"expires_at":    k.ExpiresAt,
			"last_used_at":  k.LastUsedAt,
			"revoked_at":    k.RevokedAt,
			"created_by":    k.CreatedBy,
		}
	}
	return writeAPIKeyJSON(cmd, out, pretty)
}

// runAPIKeyRevoke marks the key with the given ID as administratively disabled.
func runAPIKeyRevoke(cmd *cobra.Command, args []string) error {
	s, err := openStore(cmd)
	if err != nil {
		return err
	}
	defer s.Close()

	if err := s.RevokeAPIKey(context.Background(), args[0]); err != nil {
		return fmt.Errorf("revoke api key: %w", err)
	}
	fmt.Fprintln(cmd.ErrOrStderr(), "revoked", args[0])
	return nil
}

// cleanScope returns the scope slice with empty strings and duplicates removed.
// Empty input becomes the wildcard scope so callers cannot accidentally mint a
// no-access key.
func cleanScope(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, e := range in {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, ok := seen[e]; ok {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	if len(out) == 0 {
		return []string{store.ScopeWildcard}
	}
	return out
}

// writeAPIKeyJSON marshals v as JSON to stdout, indented when pretty is true.
func writeAPIKeyJSON(cmd *cobra.Command, v any, pretty bool) error {
	enc := json.NewEncoder(cmd.OutOrStdout())
	if pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(v)
}
