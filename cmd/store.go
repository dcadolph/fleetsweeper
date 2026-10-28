package cmd

import (
	"github.com/spf13/cobra"

	"github.com/dcadolph/fleetsweeper/internal/store"
)

// openAnyStore opens whichever backend the --db / --db-driver flag pair points
// at. Returns the broader Store interface so callers can use either backend
// transparently.
func openAnyStore(cmd *cobra.Command) (store.Store, error) {
	dbPath, _ := cmd.Flags().GetString("db")
	if dbPath == "" {
		return nil, ErrNoDatabase
	}
	driver, _ := cmd.Flags().GetString("db-driver")
	if driver == "" {
		driver = string(store.DetectDriver(dbPath))
	}
	return store.Open(driver, dbPath)
}
