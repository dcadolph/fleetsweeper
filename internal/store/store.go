package store

import (
	"context"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// ScanRecord represents a persisted scan execution.
type ScanRecord struct {
	// ID is the unique scan identifier (ULID).
	ID string `json:"id"`
	// Timestamp is when the scan was executed.
	Timestamp time.Time `json:"timestamp"`
	// Clusters lists the cluster context names that were scanned.
	Clusters []string `json:"clusters"`
	// Scanners lists the scanner names that were executed.
	Scanners []string `json:"scanners"`
}

// ScanResultRecord represents one scanner's output for one cluster in one scan.
type ScanResultRecord struct {
	// ScanID is the parent scan identifier.
	ScanID string `json:"scan_id"`
	// Cluster is the cluster context name.
	Cluster string `json:"cluster"`
	// Scanner is the scanner name.
	Scanner string `json:"scanner"`
	// DataJSON is the raw JSON-encoded scanner output.
	DataJSON []byte `json:"data_json"`
}

// ClusterRecord represents a known cluster.
type ClusterRecord struct {
	// Name is the kubeconfig context name.
	Name string `json:"name"`
	// FirstSeen is when this cluster was first scanned.
	FirstSeen time.Time `json:"first_seen"`
	// LastSeen is when this cluster was last scanned.
	LastSeen time.Time `json:"last_seen"`
	// Groups lists the group names this cluster belongs to.
	Groups []string `json:"groups"`
}

// GroupRecord represents a cluster group.
type GroupRecord struct {
	// Name is the group name.
	Name string `json:"name"`
	// Clusters lists the cluster names in this group.
	Clusters []string `json:"clusters"`
}

// Store persists and retrieves scan data.
type Store interface {
	// SaveScan persists a complete scan with all per-cluster results. Returns
	// the generated scan ID.
	SaveScan(ctx context.Context, clusters []string, results map[string]map[string]scanner.Result) (string, error)

	// GetScan retrieves a scan record by ID.
	GetScan(ctx context.Context, id string) (*ScanRecord, error)

	// ListScans returns scan records ordered by timestamp descending.
	ListScans(ctx context.Context, limit int) ([]ScanRecord, error)

	// GetScanResults retrieves all per-cluster scanner results for a scan,
	// reconstructed into the same map shape the scan engine produces.
	GetScanResults(ctx context.Context, scanID string) (map[string]map[string]scanner.Result, error)

	// ListClusters returns all known clusters.
	ListClusters(ctx context.Context) ([]ClusterRecord, error)

	// SaveGroup creates or updates a group with the given cluster members.
	SaveGroup(ctx context.Context, name string, clusters []string) error

	// GetGroup retrieves a group by name.
	GetGroup(ctx context.Context, name string) (*GroupRecord, error)

	// ListGroups returns all groups.
	ListGroups(ctx context.Context) ([]GroupRecord, error)

	// DeleteGroup removes a group.
	DeleteGroup(ctx context.Context, name string) error

	// AddClusterToGroup adds a cluster to an existing group.
	AddClusterToGroup(ctx context.Context, group, cluster string) error

	// RemoveClusterFromGroup removes a cluster from a group.
	RemoveClusterFromGroup(ctx context.Context, group, cluster string) error

	// GetClusterHistory returns scan results for a specific cluster across
	// scans, ordered by time descending.
	GetClusterHistory(ctx context.Context, cluster string, limit int) ([]ScanResultRecord, error)

	// GetScansByTimeRange returns scans within a time window.
	GetScansByTimeRange(ctx context.Context, start, end time.Time) ([]ScanRecord, error)

	// Close releases database resources.
	Close() error
}
