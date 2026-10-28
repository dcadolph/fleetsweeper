package cmd

import (
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

// TestStoreCommandsHonorPostgresDSN verifies offline store commands open a Postgres DSN with the
// Postgres driver rather than handing it to SQLite as a file path.
func TestStoreCommandsHonorPostgresDSN(t *testing.T) {
	t.Parallel()
	const dsn = "postgres://u:p@127.0.0.1:1/x"
	tests := []struct {
		Name string
		Run  func(cmd *cobra.Command, args []string) error
	}{{ // Test 0: group list.
		Name: "group list", Run: runGroupList,
	}, { // Test 1: history list.
		Name: "history list", Run: runHistoryList,
	}, { // Test 2: apikey list.
		Name: "apikey list", Run: runAPIKeyList,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			cmd := newStoreCmd(dsn)
			cmd.Flags().Int("limit", 10, "")
			err := test.Run(cmd, nil)
			if err == nil {
				t.Fatalf("%s: want a connection error, got nil", test.Name)
			}
			if strings.Contains(strings.ToLower(err.Error()), "sqlite") {
				t.Errorf("%s: DSN opened as SQLite: %v", test.Name, err)
			}
		})
	}
}
