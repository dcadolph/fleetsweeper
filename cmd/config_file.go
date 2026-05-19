package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"go.yaml.in/yaml/v3"
)

// applyConfigFile reads a YAML config file and applies each key as the
// corresponding flag value on cmd. Keys map directly to flag names (e.g.
// "auth-token: secret"). Already-supplied CLI flags win over file values so
// operators can override one-off settings without editing their config.
//
// The function is a no-op when --config is empty.
func applyConfigFile(cmd *cobra.Command) error {
	path, _ := cmd.Flags().GetString("config")
	if path == "" {
		return nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read config %q: %w", path, err)
	}
	var values map[string]any
	if err := yaml.Unmarshal(raw, &values); err != nil {
		return fmt.Errorf("parse config %q: %w", path, err)
	}

	for key, val := range values {
		flag := cmd.Flags().Lookup(key)
		if flag == nil {
			return fmt.Errorf("config %q: unknown flag %q", path, key)
		}
		if flag.Changed {
			continue
		}
		switch v := val.(type) {
		case string:
			if err := cmd.Flags().Set(key, v); err != nil {
				return fmt.Errorf("config %q: set %s: %w", path, key, err)
			}
		case bool:
			if v {
				_ = cmd.Flags().Set(key, "true")
			} else {
				_ = cmd.Flags().Set(key, "false")
			}
		case int, int64, float64:
			if err := cmd.Flags().Set(key, fmt.Sprintf("%v", v)); err != nil {
				return fmt.Errorf("config %q: set %s: %w", path, key, err)
			}
		case []any:
			parts := make([]string, len(v))
			for i, item := range v {
				parts[i] = fmt.Sprintf("%v", item)
			}
			if err := cmd.Flags().Set(key, strings.Join(parts, ",")); err != nil {
				return fmt.Errorf("config %q: set %s: %w", path, key, err)
			}
		default:
			return fmt.Errorf("config %q: unsupported type %T for key %q", path, val, key)
		}
	}
	return nil
}
