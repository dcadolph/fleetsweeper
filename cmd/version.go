package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Set via ldflags at build time.
var (
	buildVersion = "dev"
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

// versionCmd prints build version information.
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version",
	Run: func(c *cobra.Command, _ []string) {
		fmt.Fprintf(c.OutOrStderr(), "fleetsweeper %s (%s) built %s\n", buildVersion, buildCommit, buildDate)
	},
}
