package store

import (
	"context"
	"time"

	"github.com/dcadolph/fleetsweeper/internal/scanner"
)

// ScanRecord represents a persisted scan execution.
type ScanRecord struct {
	// ID is the unique, time-sortable scan identifier.
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
	// Tags is the cluster's free-form tag map, omitted from the wire
	// when no tags are set.
	Tags map[string]string `json:"tags,omitempty"`
}

// GroupRecord represents a cluster group.
type GroupRecord struct {
	// Name is the group name.
	Name string `json:"name"`
	// Clusters lists the cluster names in this group.
	Clusters []string `json:"clusters"`
}

// LocationRecord is a user-supplied geographic override for a cluster. This
// is how operators map clusters to physical sites (retail stores, factories,
// edge devices) that have no cloud-region label to auto-detect.
type LocationRecord struct {
	// Cluster is the cluster context name.
	Cluster string `json:"cluster"`
	// Lat is latitude in degrees north (positive) or south (negative).
	Lat float64 `json:"lat"`
	// Lng is longitude in degrees east (positive) or west (negative).
	Lng float64 `json:"lng"`
	// Site is a human-readable label (for example "Store #42, Manhattan").
	Site string `json:"site,omitempty"`
	// Notes is free-form text the operator can use.
	Notes string `json:"notes,omitempty"`
	// UpdatedAt is when the record was last written.
	UpdatedAt time.Time `json:"updated_at"`
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

	// Prune deletes scans older than cutoff. Returns the number of scans deleted.
	Prune(ctx context.Context, cutoff time.Time) (int, error)

	// Vacuum reclaims unused database pages.
	Vacuum(ctx context.Context) error

	// SetLocation upserts a manual location override for a cluster.
	SetLocation(ctx context.Context, loc LocationRecord) error

	// GetLocation returns a single cluster's manual override, or nil if none.
	GetLocation(ctx context.Context, cluster string) (*LocationRecord, error)

	// ListLocations returns every manual override.
	ListLocations(ctx context.Context) ([]LocationRecord, error)

	// DeleteLocation removes a manual override.
	DeleteLocation(ctx context.Context, cluster string) error

	// SaveAck upserts a finding acknowledgement. The fingerprint primary key
	// allows the same finding to be acked once across many scan cycles.
	SaveAck(ctx context.Context, rec AckRecord) error

	// DeleteAck removes an acknowledgement. Idempotent.
	DeleteAck(ctx context.Context, fingerprint string) error

	// ListAcks returns every active acknowledgement (expired snoozes pruned).
	ListAcks(ctx context.Context) ([]AckRecord, error)

	// IsAcked reports whether a finding is currently acknowledged.
	IsAcked(ctx context.Context, fingerprint string) (bool, error)

	// SaveAPIKey inserts a new API key. The raw token is never persisted: the
	// caller must hash it and place the result in rec.TokenHash before calling.
	SaveAPIKey(ctx context.Context, rec APIKeyRecord) error

	// GetAPIKeyByHash looks up a key by token hash. Returns the wrapped
	// ErrNotFound when no row matches.
	GetAPIKeyByHash(ctx context.Context, hash string) (*APIKeyRecord, error)

	// GetAPIKey returns the key with the given ID.
	GetAPIKey(ctx context.Context, id string) (*APIKeyRecord, error)

	// ListAPIKeys returns every API key including revoked ones, newest first.
	ListAPIKeys(ctx context.Context) ([]APIKeyRecord, error)

	// RevokeAPIKey marks the key with the given ID as administratively disabled.
	RevokeAPIKey(ctx context.Context, id string) error

	// TouchAPIKey updates the last-used-at timestamp. Best-effort; callers
	// should not fail authentication on error.
	TouchAPIKey(ctx context.Context, id string, at time.Time) error

	// SaveAuditEntry inserts one audit log row.
	SaveAuditEntry(ctx context.Context, rec AuditEntry) error

	// ListAuditEntries returns audit entries matching opts, newest first.
	ListAuditEntries(ctx context.Context, opts AuditListOptions) ([]AuditEntry, error)

	// PruneAuditEntries deletes audit log rows older than cutoff and returns
	// the number of rows removed. Used by the audit-retention ticker.
	PruneAuditEntries(ctx context.Context, cutoff time.Time) (int, error)

	// UpsertAlert inserts or updates an inbound AlertManager alert keyed by
	// its fingerprint. Reusing the fingerprint allows the same alert to
	// transition between firing/resolved without producing duplicate rows.
	UpsertAlert(ctx context.Context, rec AlertRecord) error

	// GetAlert returns the alert row with the given fingerprint. Returns
	// ErrNotFound when no row matches.
	GetAlert(ctx context.Context, fingerprint string) (*AlertRecord, error)

	// ListAlerts returns alerts matching opts, newest received_at first.
	ListAlerts(ctx context.Context, opts AlertListOptions) ([]AlertRecord, error)

	// PruneAlerts deletes alert rows older than cutoff (received_at). Returns
	// the number of rows removed.
	PruneAlerts(ctx context.Context, cutoff time.Time) (int, error)

	// SetClusterTag upserts a single key/value tag on a cluster.
	SetClusterTag(ctx context.Context, cluster, key, value string) error

	// DeleteClusterTag removes one key from a cluster's tag set. Idempotent.
	DeleteClusterTag(ctx context.Context, cluster, key string) error

	// GetClusterTags returns every tag pair on a cluster as a key→value
	// map. Empty map when no tags are set.
	GetClusterTags(ctx context.Context, cluster string) (map[string]string, error)

	// ListClusterTags returns every tag across the fleet, grouped by
	// cluster. Convenient for the dashboard's per-cluster render.
	ListClusterTags(ctx context.Context) (map[string]map[string]string, error)

	// Close releases database resources.
	Close() error
}
