package version

import (
	"context"
	"fmt"

	"github.com/dcadolph/fleetsweeper/internal/kube"
	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// Name is the registry key for this scanner.
const Name = "version"

// Data holds Kubernetes server version information for one cluster.
type Data struct {
	// Major is the major version number.
	Major string `json:"major"`
	// Minor is the minor version number.
	Minor string `json:"minor"`
	// GitVersion is the full version string (e.g. v1.28.3).
	GitVersion string `json:"git_version"`
	// Platform is the server platform (e.g. linux/amd64).
	Platform string `json:"platform"`
}

// NewScanner returns a scanner that retrieves the Kubernetes server version.
func NewScanner() scanner.Scanner {
	return scanner.ScannerFunc(func(ctx context.Context, client *kube.Client) (scanner.Result, error) {
		info, err := client.Clientset().Discovery().ServerVersion()
		if err != nil {
			return scanner.Result{}, fmt.Errorf("%w: %s: %w", scanner.ErrScan, Name, err)
		}
		return scanner.Result{
			Scanner: Name,
			Data: Data{
				Major:      info.Major,
				Minor:      info.Minor,
				GitVersion: info.GitVersion,
				Platform:   info.Platform,
			},
		}, nil
	})
}
