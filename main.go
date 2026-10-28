// Fleetsweeper scans Kubernetes clusters across a fleet and compares them, reporting
// configuration divergence, outliers, and findings from the CLI or a served dashboard.
package main

import "github.com/dcadolph/fleetsweeper/cmd"

func main() { cmd.Execute() }
