package cmd

import (
	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// openStore opens the SQLite store from the --db flag value.
func openStore(cmd *cobra.Command) (*store.SQLite, error) {
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath == "" {
		return nil, ErrNoDatabase
	}
	return store.NewSQLite(dbPath)
}
